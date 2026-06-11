import hashlib
import hmac

from bugbot.server.auth import (
    BitbucketIPAllowlist,
    client_ip,
    verify_hmac_signature,
)


def _sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_hmac_accepts_correct_signature():
    body = b'{"pullrequest":{"id":1}}'
    assert verify_hmac_signature(body=body, header=_sign(body, "topsecret"), secret="topsecret")


def test_hmac_rejects_wrong_signature():
    body = b'{"pullrequest":{"id":1}}'
    assert not verify_hmac_signature(
        body=body, header=_sign(body, "wrong"), secret="topsecret",
    )


def test_hmac_rejects_missing_header():
    assert not verify_hmac_signature(body=b"x", header=None, secret="s")


def test_hmac_rejects_wrong_algorithm_prefix():
    body = b"x"
    bad = "sha1=" + hmac.new(b"s", body, hashlib.sha1).hexdigest()
    assert not verify_hmac_signature(body=body, header=bad, secret="s")


def test_client_ip_uses_peer_when_proxy_not_trusted():
    assert client_ip(peer="9.9.9.9", forwarded_for="1.2.3.4, 5.6.7.8",
                     trust_forwarded=False) == "9.9.9.9"


def test_client_ip_honours_xff_when_proxy_trusted():
    assert client_ip(peer="9.9.9.9", forwarded_for="1.2.3.4, 5.6.7.8",
                     trust_forwarded=True) == "1.2.3.4"


def test_ip_allowlist_admits_ip_in_range(monkeypatch):
    al = BitbucketIPAllowlist(refresh_seconds=3600)
    monkeypatch.setattr(
        al, "_fetch",
        lambda: __import__("ipaddress").ip_network("18.234.32.224/28")
        and [__import__("ipaddress").ip_network("18.234.32.224/28")],
    )
    # First call populates the cache.
    assert al.is_allowed("18.234.32.225") is True
    assert al.is_allowed("8.8.8.8") is False


def test_ip_allowlist_fail_open_on_first_run_fetch_error(monkeypatch):
    al = BitbucketIPAllowlist(refresh_seconds=3600)

    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(al, "_fetch", boom)
    # No cache, fetch failed → fail open exactly once.
    assert al.is_allowed("1.2.3.4") is True


def test_ip_allowlist_fail_closed_after_first_success(monkeypatch):
    import ipaddress
    al = BitbucketIPAllowlist(refresh_seconds=0)  # always refresh
    monkeypatch.setattr(al, "_fetch", lambda: [ipaddress.ip_network("10.0.0.0/8")])
    assert al.is_allowed("10.0.0.1") is True

    # Now make refresh fail. We still have the previous cache → fail closed
    # for outside IPs.
    def boom():
        raise RuntimeError("dns died")

    monkeypatch.setattr(al, "_fetch", boom)
    assert al.is_allowed("8.8.8.8") is False
    assert al.is_allowed("10.0.0.2") is True
