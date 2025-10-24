from server.security import make_signature, verify_signature


def test_hmac_roundtrip():
    secret = "testsecret"
    ts = "1698140000"
    body = '{"a":1,"b":2}'
    sig = make_signature(secret, ts, body)
    assert verify_signature(secret, ts, body, sig)


def test_hmac_invalid():
    secret = "s1"
    ts = "1698140000"
    body = "{}"
    sig = make_signature(secret, ts, body)
    assert not verify_signature("othersecret", ts, body, sig)
