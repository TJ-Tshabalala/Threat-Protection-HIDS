from fastapi.testclient import TestClient
from server.main import app
import secrets


def test_provision_and_rotate(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "adminkey")
    monkeypatch.setenv("MASTER_KEY", "test-master-key-please-replace")
    monkeypatch.setenv("HIDS_DB", str(tmp_path / "hids.db"))
    client = TestClient(app)

    # provision: create new agent secret server-side
    r = client.post("/agents/provision", json={"agent_id": "prov1", "hostname": "h1"}, headers={"x-api-key": "adminkey"})
    assert r.status_code == 200
    data = r.json()
    # server should now return a one-time token (not the plaintext secret)
    assert "token" in data and isinstance(data["token"], str)
    token = data["token"]

    # agent fetches its secret exactly once using the token
    r_secret = client.get(f"/agents/secret?token={token}")
    assert r_secret.status_code == 200
    secret = r_secret.json().get("secret")
    assert isinstance(secret, str) and len(secret) > 0

    # second fetch should fail (token consumed)
    r_secret2 = client.get(f"/agents/secret?token={token}")
    assert r_secret2.status_code == 404

    # rotate: rotate the secret
    new_secret = secrets.token_urlsafe(16)
    r2 = client.post("/agents/rotate", json={"agent_id": "prov1", "new_secret": new_secret}, headers={"x-api-key": "adminkey"})
    assert r2.status_code == 200
    data2 = r2.json()
    assert "token" in data2 and isinstance(data2["token"], str)
    token2 = data2["token"]

    # fetch rotated secret and ensure it matches the admin-supplied value
    r_rot = client.get(f"/agents/secret?token={token2}")
    assert r_rot.status_code == 200
    assert r_rot.json().get("secret") == new_secret

    # token cannot be reused
    assert client.get(f"/agents/secret?token={token2}").status_code == 404
