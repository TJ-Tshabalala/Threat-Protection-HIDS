"""HMAC signing and verification utilities for agent-server authentication."""
import hmac
import hashlib
from typing import Tuple


def make_signature(secret: str, timestamp: str, body: str) -> str:
    """Return hex HMAC-SHA256 of timestamp + '.' + body using secret."""
    if isinstance(secret, str):
        secret = secret.encode()
    msg = (timestamp + "." + body).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_signature(secret: str, timestamp: str, body: str, signature: str) -> bool:
    expected = make_signature(secret, timestamp, body)
    # Use hmac.compare_digest to avoid timing attacks
    return hmac.compare_digest(expected, signature)
