"""Webhook authentication: HMAC signature + Bitbucket IP allowlist.

Bitbucket Cloud webhooks
------------------------
When you set a secret on a webhook, Bitbucket signs the raw body with
HMAC-SHA256 and sends the digest in `X-Hub-Signature` as `sha256=<hex>`.
This is the same format GitHub uses.

Reference: https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/

IP allowlist
------------
Atlassian publishes outbound IP ranges at:
    https://ip-ranges.atlassian.com/
We cache the list in-process and refresh periodically. If the fetch fails
we **fail open on first run** (we don't want to brick the service on
network blips) but **fail closed once we've ever had a successful fetch**
— meaning once we have a known list, anything outside it is rejected.
"""

from __future__ import annotations

import hmac
import ipaddress
import threading
import time
from dataclasses import dataclass
from hashlib import sha256

import httpx

from bugbot.libs.logging import get_logger

log = get_logger("auth")

_ATLASSIAN_IP_URL = "https://ip-ranges.atlassian.com/"


def verify_hmac_signature(*, body: bytes, header: str | None, secret: str) -> bool:
    """Constant-time HMAC-SHA256 check against `sha256=<hex>` header."""
    if not header or not header.startswith("sha256="):
        return False
    provided = header.removeprefix("sha256=").strip()
    expected = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


@dataclass
class _CacheEntry:
    networks: list[ipaddress._BaseNetwork]
    fetched_at: float


class BitbucketIPAllowlist:
    """Caches Atlassian's published outbound IP ranges."""

    def __init__(self, *, refresh_seconds: int = 3600, timeout: float = 10.0) -> None:
        self._refresh = refresh_seconds
        self._timeout = timeout
        self._cache: _CacheEntry | None = None
        self._lock = threading.Lock()

    def _fetch(self) -> list[ipaddress._BaseNetwork]:
        with httpx.Client(timeout=self._timeout) as c:
            resp = c.get(_ATLASSIAN_IP_URL)
        resp.raise_for_status()
        data = resp.json()
        nets: list[ipaddress._BaseNetwork] = []
        for item in data.get("items", []):
            cidr = item.get("cidr")
            if not cidr:
                continue
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        if not nets:
            raise RuntimeError("Atlassian IP feed returned no usable CIDRs")
        return nets

    def _ensure(self) -> list[ipaddress._BaseNetwork] | None:
        now = time.time()
        with self._lock:
            cache = self._cache
            if cache and (now - cache.fetched_at) < self._refresh:
                return cache.networks
            try:
                nets = self._fetch()
            except Exception as exc:
                log.warning("could not refresh Atlassian IP allowlist: {}", exc)
                # Fail-open on first run; fail-closed if we had a list.
                return cache.networks if cache else None
            self._cache = _CacheEntry(networks=nets, fetched_at=now)
            log.info("refreshed Atlassian IP allowlist ({} CIDRs)", len(nets))
            return nets

    def is_allowed(self, ip: str) -> bool:
        nets = self._ensure()
        if nets is None:
            # First call ever and we couldn't fetch. Fail open exactly once.
            log.warning("IP allowlist unavailable — admitting {} (first-run fail-open)", ip)
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in nets)


def client_ip(*, peer: str, forwarded_for: str | None, trust_forwarded: bool) -> str:
    """Resolve the client IP. Only honour XFF when we trust the proxy."""
    if trust_forwarded and forwarded_for:
        # First IP in the list is the original client.
        return forwarded_for.split(",")[0].strip()
    return peer
