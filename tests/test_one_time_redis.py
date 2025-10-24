import os
import pytest

try:
    import redis
except Exception:
    redis = None

from server import one_time_redis


@pytest.mark.skipif(not os.getenv("REDIS_URL"), reason="REDIS_URL not set")
def test_redis_one_time_token_roundtrip():
    # This test runs only when REDIS_URL is set (CI will set this with a Redis service)
    client = redis.from_url(os.getenv("REDIS_URL"))
    # Clear any test keys with our prefix to be safe
    keys = client.keys("hids:ott:*")
    if keys:
        client.delete(*keys)

    agent_id = "test-agent-redis"
    secret = "s3cr3t-value"
    token = one_time_redis.make_one_time_token(agent_id, secret, ttl=10)
    assert isinstance(token, str)

    # Consume the token
    got = one_time_redis.consume_one_time_token(token)
    assert got == secret

    # Consuming again should return None
    got2 = one_time_redis.consume_one_time_token(token)
    assert got2 is None

    # Clean up
    k = f"hids:ott:{token}"
    client.delete(k)
