"""Redis-backed nonce cache for replay protection.

This module provides is_replay(agent_id, signature, window_seconds) using
Redis SETNX with expiry so multiple server instances share seen nonces.
"""
import os
import redis

_client = None


def _get_client():
    global _client
    if _client is None:
        url = os.getenv("REDIS_URL")
        if not url:
            raise RuntimeError("REDIS_URL not configured")
        _client = redis.from_url(url, decode_responses=True)
    return _client


def is_replay(agent_id: str, signature: str, window_seconds: int = 300) -> bool:
    """Return True if the signature was seen within window_seconds, otherwise record and return False.

    Implementation: use key = f"hids:nonce:{agent_id}:{signature}" and SETNX with expiry window_seconds.
    If SETNX returns 1 (set), it's first-seen and not a replay. If 0, it's a replay.
    """
    client = _get_client()
    key = f"hids:nonce:{agent_id}:{signature}"
    # SETNX -> set if not exists
    added = client.set(key, "1", nx=True, ex=window_seconds)
    return not bool(added)
