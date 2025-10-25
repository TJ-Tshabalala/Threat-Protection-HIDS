import json
import os
import sqlite3
import base64
from datetime import datetime
from typing import Optional, Dict, Any

from argon2 import PasswordHasher
from cryptography.fernet import Fernet

DB_PATH = os.getenv("HIDS_DB", "./hids.sqlite3")
_ph = PasswordHasher()


def _get_fernet():
    master = os.getenv("MASTER_KEY")
    if not master:
        raise RuntimeError("MASTER_KEY not set; required to encrypt/decrypt agent secrets")
    # Derive a 32-byte key. If user supplies a base64 key, accept it; otherwise derive from value.
    try:
        # try if provided value is valid base64 key
        Fernet(master)
        key = master
    except Exception:
        # derive deterministic key from provided string
        import hashlib

        digest = hashlib.sha256(master.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def _db_path(path: Optional[str] = None) -> str:
    return path or os.getenv("HIDS_DB", DB_PATH)


def init_db(path: Optional[str] = None):
    p = _db_path(path)
    conn = sqlite3.connect(p)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            secret_hash TEXT,
            secret_enc TEXT,
            metadata TEXT,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def add_or_update_agent(agent_id: str, hostname: str, secret_plain: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
    conn = sqlite3.connect(_db_path(None))
    cur = conn.cursor()
    meta_json = json.dumps(metadata or {})
    secret_hash = None
    secret_enc = None
    if secret_plain:
        secret_hash = _ph.hash(secret_plain)
        f = _get_fernet()
        secret_enc = f.encrypt(secret_plain.encode()).decode()

    cur.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
    exists = cur.fetchone()
    now = datetime.utcnow().isoformat()
    if exists:
        cur.execute(
            "UPDATE agents SET hostname = ?, secret_hash = COALESCE(?, secret_hash), secret_enc = COALESCE(?, secret_enc), metadata = ?, created_at = ? WHERE agent_id = ?",
            (hostname, secret_hash, secret_enc, meta_json, now, agent_id),
        )
    else:
        cur.execute(
            "INSERT INTO agents (agent_id, hostname, secret_hash, secret_enc, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, hostname, secret_hash, secret_enc, meta_json, now),
        )
    conn.commit()
    conn.close()


def rotate_agent_secret(agent_id: str, new_secret_plain: str):
    """Rotate the stored secret for an agent to new_secret_plain."""
    conn = sqlite3.connect(_db_path(None))
    cur = conn.cursor()
    secret_hash = _ph.hash(new_secret_plain)
    f = _get_fernet()
    secret_enc = f.encrypt(new_secret_plain.encode()).decode()
    cur.execute("UPDATE agents SET secret_hash = ?, secret_enc = ? WHERE agent_id = ?", (secret_hash, secret_enc, agent_id))
    conn.commit()
    conn.close()


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(_db_path(None))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    meta = json.loads(row["metadata"]) if row["metadata"] else {}
    secret_plain = None
    if row["secret_enc"]:
        try:
            f = _get_fernet()
            secret_plain = f.decrypt(row["secret_enc"].encode()).decode()
        except Exception:
            secret_plain = None
    return {
        "agent_id": row["agent_id"],
        "hostname": row["hostname"],
        "secret_hash": row["secret_hash"],
        "secret": secret_plain,
        "metadata": meta,
        "created_at": row["created_at"],
    }


def reencrypt_master(old_master: str, new_master: str, path: Optional[str] = None) -> int:
    """Re-encrypt all stored agent secrets using a new master key.

    Returns the number of records re-encrypted.
    """
    # build Fernet objects from provided master strings
    def _fernet_from_master(master_val: str):
        import hashlib

        try:
            from cryptography.fernet import Fernet as _F

            # if master_val is already base64 Fernet key, use it
            try:
                _F(master_val)
                key = master_val
            except Exception:
                digest = hashlib.sha256(master_val.encode()).digest()
                key = base64.urlsafe_b64encode(digest)
            return _F(key)
        except Exception as e:
            raise e

    old_f = _fernet_from_master(old_master)
    new_f = _fernet_from_master(new_master)

    conn = sqlite3.connect(_db_path(path))
    cur = conn.cursor()
    cur.execute("SELECT agent_id, secret_enc FROM agents WHERE secret_enc IS NOT NULL")
    rows = cur.fetchall()
    count = 0
    for aid, secret_enc in rows:
        try:
            # decrypt using old key
            plain = old_f.decrypt(secret_enc.encode()).decode()
            # encrypt with new key
            new_enc = new_f.encrypt(plain.encode()).decode()
            cur.execute("UPDATE agents SET secret_enc = ? WHERE agent_id = ?", (new_enc, aid))
            count += 1
        except Exception:
            # skip records that cannot be decrypted (old_master wrong)
            continue
    conn.commit()
    conn.close()
    return count
