"""Webhook authentication: HMAC signature + per-provider IP allowlists.

HMAC signing
------------
Both Bitbucket and GitHub sign the **raw body** with HMAC-SHA256 and send
the digest as `sha256=<hex>`. Header name differs:

  * Bitbucket: `X-Hub-Signature`
  * GitHub:    `X-Hub-Signature-256`

The verification logic is identical — we expose one helper and let the
caller pick which header to feed it.

IP allowlist
------------
Each provider publishes its webhook source CIDRs:

  * Bitbucket (Atlassian): https://ip-ranges.atlassian.com/  (`items[].cidr`)
  * GitHub:                https://api.github.com/meta       (`hooks[]`)

We cache in-process per allowlist and refresh on a TTL. **Fail open on the
very first fetch failure** (we don't want to brick the service on a
network blip) but **fail closed thereafter** — once we've ever had a
known list, traffic outside it gets 403.
"""

from __future__ import annotations

import hmac
import ipaddress
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

import httpx

from bugbot.libs.logging import get_logger

log = get_logger("auth")

_ATLASSIAN_IP_URL = "https://ip-ranges.atlassian.com/"
_GITHUB_META_URL = "https://api.github.com/meta"


def verify_hmac_signature(*, body: bytes, header: str | None, secret: str) -> bool:
    """Constant-time HMAC-SHA256 check against `sha256=<hex>` header.

    Works for both Bitbucket (`X-Hub-Signature`) and GitHub
    (`X-Hub-Signature-256`) — the on-wire format is identical.
    """
    if not header or not header.startswith("sha256="):
        return False
    provided = header.removeprefix("sha256=").strip()
    expected = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


@dataclass
class _CacheEntry:
    networks: list[ipaddress._BaseNetwork]
    fetched_at: float


def _parse_bitbucket_cidrs(data: dict) -> list[str]:
    return [
        item.get("cidr")
        for item in data.get("items") or []
        if item.get("cidr")
    ]


def _parse_github_cidrs(data: dict) -> list[str]:
    # GitHub's /meta returns `hooks` as a flat list of CIDR strings —
    # specifically the source IPs webhooks come from. Other keys
    # (`web`, `api`, `actions`, …) are outbound destinations for *our*
    # traffic, not theirs, so we don't include them.
    return list(data.get("hooks") or [])


class _IPAllowlistBase:
    """Shared cache+fetch logic for any JSON-feed-backed allowlist."""

    name: str = "ip-allowlist"
    url: str = ""
    _parse: Callable[[dict], list[str]] = staticmethod(lambda _d: [])

    def __init__(self, *, refresh_seconds: int = 3600, timeout: float = 10.0) -> None:
        self._refresh = refresh_seconds
        self._timeout = timeout
        self._cache: _CacheEntry | None = None
        self._lock = threading.Lock()

    def _fetch(self) -> list[ipaddress._BaseNetwork]:
        with httpx.Client(timeout=self._timeout) as c:
            resp = c.get(self.url)
        resp.raise_for_status()
        data = resp.json()
        nets: list[ipaddress._BaseNetwork] = []
        for cidr in type(self)._parse(data):
            if not cidr:
                continue
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        if not nets:
            raise RuntimeError(f"{self.name} feed returned no usable CIDRs")
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
                log.warning("could not refresh {}: {}", self.name, exc)
                return cache.networks if cache else None
            self._cache = _CacheEntry(networks=nets, fetched_at=now)
            log.info("refreshed {} ({} CIDRs)", self.name, len(nets))
            return nets

    def is_allowed(self, ip: str) -> bool:
        nets = self._ensure()
        if nets is None:
            log.warning(
                "{} unavailable — admitting {} (first-run fail-open)",
                self.name, ip,
            )
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in nets)


class BitbucketIPAllowlist(_IPAllowlistBase):
    """Caches Atlassian's published outbound IP ranges."""

    name = "Atlassian IP allowlist"
    url = _ATLASSIAN_IP_URL
    _parse = staticmethod(_parse_bitbucket_cidrs)


class GitHubIPAllowlist(_IPAllowlistBase):
    """Caches GitHub's webhook source IP ranges (`/meta` -> `hooks`)."""

    name = "GitHub IP allowlist"
    url = _GITHUB_META_URL
    _parse = staticmethod(_parse_github_cidrs)


def client_ip(*, peer: str, forwarded_for: str | None, trust_forwarded: bool) -> str:
    """Resolve the client IP. Only honour XFF when we trust the proxy."""
    if trust_forwarded and forwarded_for:
        # First IP in the list is the original client.
        return forwarded_for.split(",")[0].strip()
    return peer
