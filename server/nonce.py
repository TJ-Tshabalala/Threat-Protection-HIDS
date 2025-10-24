"""Simple in-memory nonce cache to prevent replay attacks.

This is intentionally minimal for prototype use. For production use a distributed
store (Redis) to share nonces across instances.
"""
import threading
import time
from typing import Tuple


_lock = threading.Lock()
# store keys as (agent_id, signature) -> timestamp
_store = {}


def is_replay(agent_id: str, signature: str, window_seconds: int = 300) -> bool:
    """Return True if the (agent_id, signature) was seen within window_seconds.
    Otherwise record it and return False.
    """
    key = (agent_id, signature)
    now = int(time.time())
    with _lock:
        # cleanup old entries occasionally
        # remove items older than window_seconds*2
        cutoff = now - (window_seconds * 2)
        for k, ts in list(_store.items()):
            if ts < cutoff:
                del _store[k]

        ts = _store.get(key)
        if ts is not None and (now - ts) <= window_seconds:
            return True
        # record first seen time
        _store[key] = now
        return False
