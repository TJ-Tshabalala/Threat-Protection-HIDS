import json
import time
from fastapi.testclient import TestClient
from server.main import app


def make_sig(secret: str, ts: str, payload: dict) -> str:
    import hmac, hashlib

    try:
        body_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    except Exception:
        body_str = str(payload)
    msg = (ts + "." + body_str).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def test_event_hmac_and_replay(tmp_path, monkeypatch):
    # configure env before TestClient starts
    monkeypatch.setenv("API_KEY", "adminkey")
    monkeypatch.setenv("MASTER_KEY", "test-master-key-please-replace")
    dbfile = str(tmp_path / "hids.db")
    monkeypatch.setenv("HIDS_DB", dbfile)

    client = TestClient(app)

    # register agent with secret via metadata (admin)
    agent_id = "agent-int-1"
    secret = "int-secret"
    r = client.post("/agents/register", json={"agent_id": agent_id, "hostname": "h1", "metadata": {"secret": secret}}, headers={"x-api-key": "adminkey"})
    assert r.status_code == 200

    # send a valid event
    payload = {"a": 1}
    ts = str(int(time.time()))
    sig = make_sig(secret, ts, payload)
    headers = {"x-api-key": "adminkey", "x-agent-id": agent_id, "x-timestamp": ts, "x-signature": sig}
    r = client.post("/events", json={"agent_id": agent_id, "event_type": "telemetry", "payload": payload}, headers=headers)
    assert r.status_code == 200

    # replay: same signature again should be rejected (409)
    r2 = client.post("/events", json={"agent_id": agent_id, "event_type": "telemetry", "payload": payload}, headers=headers)
    assert r2.status_code in (409, 401)

    # out of window timestamp should be rejected (set ts far in past)
    old_ts = str(int(time.time()) - 3600)
    old_sig = make_sig(secret, old_ts, payload)
    headers_old = {"x-api-key": "adminkey", "x-agent-id": agent_id, "x-timestamp": old_ts, "x-signature": old_sig}
    r3 = client.post("/events", json={"agent_id": agent_id, "event_type": "telemetry", "payload": payload}, headers=headers_old)
    assert r3.status_code == 408
