import json
import logging
import os
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, Dict
from .security import verify_signature
from . import db
from fastapi import Depends
from . import nonce
# if REDIS_URL env is set, prefer Redis-backed nonce store
if os.getenv("REDIS_URL"):
    try:
        from .nonce_redis import is_replay as redis_is_replay
        nonce.is_replay = redis_is_replay
        logger.info("Using Redis-backed nonce cache (REDIS_URL detected)")
    except Exception as e:
        logger.warning("Failed to initialize Redis nonce cache: %s; falling back to in-memory", e)

# --- Logging setup with rotation ---
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
handler = RotatingFileHandler(LOG_DIR / "events.log", maxBytes=5 * 1024 * 1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger("hids")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
# application

# FastAPI app instance
app = FastAPI(title="Threat Protection HIDS - API")

# initialize DB at startup (requires MASTER_KEY to be set in env)


@app.on_event("startup")
def _startup():
    try:
        db.init_db()
        logger.info("DB initialized at %s", db.DB_PATH)
    except Exception as e:
        logger.warning("DB initialization skipped or failed: %s", e)

# --- Security configuration (API key, CORS) ---
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    # fail early in production; allow for local demo but log prominently
    logger.warning("API_KEY is not set — server will run without API protection (not for production)")

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",") if os.getenv("ALLOWED_ORIGINS") else []
if ALLOWED_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])


class AgentRegister(BaseModel):
    agent_id: str
    hostname: str
    metadata: Dict[str, Any] = {}


class Event(BaseModel):
    agent_id: str
    event_type: str
    payload: Dict[str, Any] = {}


class KBQuery(BaseModel):
    query: str


AGENTS: Dict[str, Dict[str, Any]] = {}

# One-time secret tokens for provisioning/rotation flows.
# Default implementation stores tokens in-memory (prototype). If REDIS_URL is set
# and Redis is available, we'll prefer a Redis-backed implementation which is
# suitable for multi-instance / HA setups.
ONE_TIME_SECRETS: Dict[str, Dict[str, Any]] = {}


def _make_one_time_token_inmem(agent_id: str, secret: str, ttl: int = 300) -> str:
    import secrets as _secrets

    token = _secrets.token_urlsafe(32)
    ONE_TIME_SECRETS[token] = {"agent_id": agent_id, "secret": secret, "expires_at": int(time.time()) + ttl}
    return token


def _consume_one_time_token_inmem(token: str) -> dict | None:
    entry = ONE_TIME_SECRETS.pop(token, None)
    if not entry:
        return None
    if int(time.time()) > entry.get("expires_at", 0):
        return None
    return {"agent_id": entry.get("agent_id"), "secret": entry.get("secret")}


# Default function handles (may be overridden to the Redis-backed functions)
_make_one_time_token = _make_one_time_token_inmem
_consume_one_time_token = _consume_one_time_token_inmem

# If REDIS_URL is configured, try to use the Redis-backed implementation
if os.getenv("REDIS_URL"):
    try:
        from .one_time_redis import make_one_time_token as _redis_make, consume_one_time_token as _redis_consume

        _make_one_time_token = _redis_make
        _consume_one_time_token = _redis_consume
        logger.info("Using Redis-backed one-time token store (REDIS_URL detected)")
    except Exception as e:
        logger.warning("Could not initialize Redis-backed one-time tokens: %s; using in-memory fallback", e)

# Provisioning JWT support (optional). If PROVISION_KEY is set, server will
# create short-lived provisioning JWTs and require agents to present them when
# fetching secrets. This prevents anonymous token fetch if tokens are leaked.
PROVISION_KEY = os.getenv("PROVISION_KEY")
try:
    if PROVISION_KEY:
        import jwt as _jwt  # type: ignore
    else:
        _jwt = None
except Exception:
    _jwt = None


def _make_provision_jwt(agent_id: str, ttl: int = 300) -> str | None:
    if not _jwt or not PROVISION_KEY:
        return None
    payload = {"agent_id": agent_id, "exp": int(time.time()) + int(os.getenv("ONE_TIME_TTL", 300))}
    return _jwt.encode(payload, PROVISION_KEY, algorithm="HS256")


def _verify_provision_jwt(token: str, agent_id: str) -> bool:
    if not _jwt or not PROVISION_KEY:
        return True
    try:
        payload = _jwt.decode(token, PROVISION_KEY, algorithms=["HS256"])  # raises on failure
        return payload.get("agent_id") == agent_id
    except Exception:
        return False


# mount the simple static dashboard (serves files from the repo dashboard/)
BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "dashboard"
if STATIC_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(STATIC_DIR), html=True), name="dashboard")


# Simple API key enforcement middleware
from starlette.middleware.base import BaseHTTPMiddleware


async def _require_api_key(request: Request, call_next):
    # allow public health endpoint and GET to dashboard
    path = request.url.path
    # allow health, dashboard and the single-use secret fetch endpoint (agents use token)
    if path == "/health" or path.startswith("/dashboard") or path == "/agents/secret":
        return await call_next(request)

    # if no API_KEY configured, allow but warn
    if not API_KEY:
        logger.warning("No API_KEY configured; allowing unauthenticated request to %s", path)
        return await call_next(request)

    key = request.headers.get("x-api-key") or request.query_params.get("api_key")
    if not key or key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


app.add_middleware(BaseHTTPMiddleware, dispatch=_require_api_key)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/agents/register")
def register_agent(req: AgentRegister):
    # Store agent metadata; allow setting a per-agent secret via metadata (only if provided)
    AGENTS[req.agent_id] = {"hostname": req.hostname, "metadata": req.metadata}
    secret = None
    if isinstance(req.metadata, dict):
        secret = req.metadata.get("secret")

    try:
        # ensure DB exists (safe no-op if already initialized)
        try:
            db.init_db()
        except Exception:
            pass
        db.add_or_update_agent(req.agent_id, req.hostname, secret_plain=secret, metadata=req.metadata)
        logger.info("agent.register persisted %s %s", req.agent_id, req.hostname)
    except Exception as e:
        logger.warning("failed to persist agent %s: %s", req.agent_id, e)

    # Also keep in-memory cache for quick lookup (optional)
    if secret:
        AGENTS[req.agent_id]["secret"] = secret

    return {"result": "registered", "agent_id": req.agent_id}


@app.post("/agents/provision")
def provision_agent(req: AgentRegister):
    """Provision an agent with a server-generated secret.

    This endpoint requires admin API_KEY (middleware enforces it). It stores the
    secret server-side and returns a short-lived one-time token that the agent
    can use to fetch the plaintext secret exactly once via `/agents/secret`.
    """
    import secrets as _secrets

    secret = _secrets.token_urlsafe(32)
    try:
        db.init_db()
    except Exception:
        pass
    db.add_or_update_agent(req.agent_id, req.hostname, secret_plain=secret, metadata=req.metadata)
    # Keep in-memory record but do NOT expose the secret here.
    AGENTS[req.agent_id] = {"hostname": req.hostname, "metadata": req.metadata}
    token = _make_one_time_token(req.agent_id, secret, ttl=int(os.getenv("ONE_TIME_TTL", 300)))
    prov_jwt = _make_provision_jwt(req.agent_id)
    logger.info("agent.provision %s token=%s", req.agent_id, token)
    resp = {"agent_id": req.agent_id, "token": token, "ttl": int(os.getenv("ONE_TIME_TTL", 300))}
    if prov_jwt:
        resp["provision_jwt"] = prov_jwt
    return resp


class AgentRotate(BaseModel):
    agent_id: str
    new_secret: str


@app.post("/agents/rotate")
def rotate_agent(r: AgentRotate):
    """Rotate an agent's secret.

    The endpoint stores the provided `new_secret` (if supplied) or generates a
    new one, and returns a one-time token the agent can use to fetch the
    plaintext secret. The token is invalidated after a single fetch.
    """
    try:
        db.init_db()
    except Exception:
        pass
    # ensure agent exists
    rec = db.get_agent(r.agent_id)
    if not rec:
        raise HTTPException(status_code=404, detail="agent not found")

    secret = r.new_secret or _make_one_time_token  # placeholder - will be replaced
    # if new_secret provided, use it; else generate
    if not r.new_secret:
        import secrets as _secrets

        secret = _secrets.token_urlsafe(32)

    db.rotate_agent_secret(r.agent_id, secret)
    # update in-memory cache without exposing secret
    if r.agent_id in AGENTS:
        AGENTS[r.agent_id].pop("secret", None)
    token = _make_one_time_token(r.agent_id, secret, ttl=int(os.getenv("ONE_TIME_TTL", 300)))
    prov_jwt = _make_provision_jwt(r.agent_id)
    logger.info("agent.rotate %s token=%s", r.agent_id, token)
    resp = {"agent_id": r.agent_id, "token": token, "ttl": int(os.getenv("ONE_TIME_TTL", 300))}
    if prov_jwt:
        resp["provision_jwt"] = prov_jwt
    return resp


@app.get("/agents/secret")
def fetch_one_time_secret(token: str, request: Request):
    """Consume a one-time token and return the secret. Token is invalidated.

    This endpoint is intentionally left unauthenticated (agents use the
    single-use token) — ensure network/TLS protections in production.
    """
    # If provisioning attestation is configured, require the agent to present
    # a short-lived provisioning JWT in the `x-provision-token` header (or as
    # query param `prov_jwt`). This endpoint accepts Request and reads headers
    # directly.
    result = _consume_one_time_token(token)
    if not result:
        raise HTTPException(status_code=404, detail="token invalid or expired")

    agent_id = result.get("agent_id")
    secret = result.get("secret")

    if PROVISION_KEY:
        prov_jwt = request.headers.get("x-provision-token") or request.query_params.get("prov_jwt")
        if not prov_jwt or not _verify_provision_jwt(prov_jwt, agent_id):
            raise HTTPException(status_code=401, detail="Missing or invalid provisioning attestation")

    return {"secret": secret}


@app.post("/events")
def receive_event(ev: Event, request: Request):
    # simple payload size check to avoid huge submissions
    try:
        size = len(json.dumps(ev.payload))
    except Exception:
        size = len(str(ev.payload))
    MAX_PAYLOAD = int(os.getenv("MAX_PAYLOAD_BYTES", 200 * 1024))
    if size > MAX_PAYLOAD:
        logger.warning("rejected oversized payload from %s: %d bytes", ev.agent_id, size)
        raise HTTPException(status_code=413, detail="Payload too large")

    # read HMAC headers from request
    agent_header = request.headers.get("x-agent-id")
    ts = request.headers.get("x-timestamp")
    sig = request.headers.get("x-signature")
    if not (agent_header and ts and sig):
        logger.warning("missing HMAC headers for event from %s", ev.agent_id)
        raise HTTPException(status_code=401, detail="Missing HMAC headers")

    # agent_id mismatches between header and body are rejected
    if agent_header != ev.agent_id:
        logger.warning("agent id mismatch header=%s body=%s", agent_header, ev.agent_id)
        raise HTTPException(status_code=401, detail="Agent ID mismatch")

    # Fetch agent secret from DB (preferred) or memory cache. Ensure DB exists.
    try:
        db.init_db()
    except Exception:
        pass
    agent_rec = db.get_agent(ev.agent_id) or AGENTS.get(ev.agent_id)
    secret = None
    if isinstance(agent_rec, dict):
        secret = agent_rec.get("secret")

    if not secret:
        logger.warning("no secret for agent %s", ev.agent_id)
        raise HTTPException(status_code=401, detail="Unknown agent or secret not configured")

    # verify signature
    try:
        body_str = json.dumps(ev.payload, separators=(",", ":"), sort_keys=True)
    except Exception:
        body_str = str(ev.payload)
    # timestamp window check
    try:
        req_ts = int(ts)
    except Exception:
        logger.warning("invalid timestamp from agent %s: %s", ev.agent_id, ts)
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    now = int(time.time())
    WINDOW = int(os.getenv("HMAC_WINDOW_SECONDS", 120))
    if abs(now - req_ts) > WINDOW:
        logger.warning("timestamp outside window for agent %s: now=%d ts=%d window=%d", ev.agent_id, now, req_ts, WINDOW)
        raise HTTPException(status_code=408, detail="Timestamp outside allowed window")

    # replay prevention: ensure signature not reused for this agent within window
    if nonce.is_replay(ev.agent_id, sig, window_seconds=WINDOW):
        logger.warning("replay detected for agent %s signature=%s", ev.agent_id, sig)
        raise HTTPException(status_code=409, detail="Replay detected")

    if not verify_signature(secret, ts, body_str, sig):
        logger.warning("signature verification failed for agent %s", ev.agent_id)
        raise HTTPException(status_code=401, detail="Invalid signature")

    logger.info("event %s from %s payload_size=%d payload=%s", ev.event_type, ev.agent_id, size, ev.payload)
    return {"result": "received"}


@app.post("/kb/query")
def kb_query(q: KBQuery):
    # Lightweight placeholder to call the AI KB module
    try:
        from ..ai.kb import query_kb
    except Exception:  # relative import may vary when running as module
        from ai.kb import query_kb

    resp = query_kb(q.query)
    if resp is None:
        raise HTTPException(status_code=500, detail="KB query failed")
    return {"result": resp}


# Simple file-backed event log reader for the dashboard
@app.get("/events/log")
def read_events_log():
    logfile = LOG_DIR / "events.log"
    if not logfile.exists():
        return {"events": []}
    with logfile.open("r") as f:
        lines = f.readlines()[-200:]
    return {"events": [l.strip() for l in lines]}
