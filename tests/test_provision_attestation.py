import os
import secrets
from fastapi.testclient import TestClient
import pytest

try:
    import jwt
except Exception:
    jwt = None

from server.main import app


@pytest.mark.skipif(not jwt, reason="PyJWT not installed")
def test_provision_and_fetch_with_jwt(monkeypatch, tmp_path):
    # Set API_KEY and PROVISION_KEY so server will include provision_jwt and require it
    monkeypatch.setenv("API_KEY", "adminkey")
    monkeypatch.setenv("PROVISION_KEY", "test-prov-key")
    monkeypatch.setenv("MASTER_KEY", "test-master-key-please-replace")
    monkeypatch.setenv("HIDS_DB", str(tmp_path / "hids.db"))

    client = TestClient(app)

    # provision: will return token and provision_jwt
    r = client.post("/agents/provision", json={"agent_id": "prov-jwt", "hostname": "h1"}, headers={"x-api-key": "adminkey"})
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert "provision_jwt" in data

    token = data["token"]
    prov_jwt = data["provision_jwt"]

    # fetch secret using header
    r2 = client.get(f"/agents/secret?token={token}", headers={"x-provision-token": prov_jwt})
    assert r2.status_code == 200
    assert isinstance(r2.json().get("secret"), str)

    # reuse token should fail
    r3 = client.get(f"/agents/secret?token={token}", headers={"x-provision-token": prov_jwt})
    assert r3.status_code == 404
