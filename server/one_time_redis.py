import os
import secrets
from typing import Optional

try:
    import redis
except Exception:
    redis = None


def _get_client():
    url = os.getenv("REDIS_URL")
    if not url:
        raise RuntimeError("REDIS_URL not set")
    if redis is None:
        raise RuntimeError("redis package not available")
    return redis.from_url(url, decode_responses=False)


def make_one_time_token(agent_id: str, secret: str, ttl: int = 300) -> str:
    """Create a one-time token stored in Redis as a HASH with TTL. Returns token."""
    client = _get_client()
    token = secrets.token_urlsafe(32)
    key = f"hids:ott:{token}"
    # Store fields in a hash and set TTL
    pipe = client.pipeline()
    pipe.hset(key, mapping={"agent_id": agent_id, "secret": secret})
    pipe.expire(key, ttl)
    pipe.execute()
    return token


def consume_one_time_token(token: str) -> Optional[dict]:
    """Atomically GET and DEL the token hash using a Lua script. Returns dict {agent_id, secret} or None."""
    client = _get_client()
    key = f"hids:ott:{token}"
    # Lua script to return all hash fields then delete the key atomically
    lua = (
        "local v = redis.call('HGETALL', KEYS[1])\n"
        "if not v or #v == 0 then return nil end\n"
        "redis.call('DEL', KEYS[1])\n"
        "return v"
    )
    try:
        res = client.eval(lua, 1, key)
    except Exception:
        return None
    if not res:
        return None
    # res is a flat list: [k1, v1, k2, v2, ...]
    try:
        it = iter(res)
        d = dict(zip(it, it))
        # Values are bytes; decode if necessary
        raw_secret = d.get(b"secret") or d.get("secret")
        raw_agent = d.get(b"agent_id") or d.get("agent_id")
        if isinstance(raw_secret, bytes):
            raw_secret = raw_secret.decode()
        if isinstance(raw_agent, bytes):
            raw_agent = raw_agent.decode()
        return {"agent_id": raw_agent, "secret": raw_secret}
    except Exception:
        return None
