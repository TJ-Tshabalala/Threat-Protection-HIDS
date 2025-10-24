import os
import tempfile
from server import db
from server.security import make_signature, verify_signature


def test_db_agent_store_and_retrieve(tmp_path, monkeypatch):
    # Set MASTER_KEY for encryption
    monkeypatch.setenv("MASTER_KEY", "test-master-key-please-replace")
    # Use a temp DB
    db_path = str(tmp_path / "test.sqlite3")
    monkeypatch.setenv("HIDS_DB", db_path)
    db.init_db(db_path)

    agent_id = "agent-db-1"
    secret = "supersecret"
    db.add_or_update_agent(agent_id, "host1", secret_plain=secret, metadata={"role": "test"})

    rec = db.get_agent(agent_id)
    assert rec is not None
    assert rec["agent_id"] == agent_id
    assert rec["secret"] == secret

    # roundtrip verify
    ts = "1698140000"
    body = '{"z":1}'
    sig = make_signature(secret, ts, body)
    assert verify_signature(secret, ts, body, sig)
