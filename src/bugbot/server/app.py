"""FastAPI app — webhook endpoints (Bitbucket + GitHub) + healthcheck.

Endpoints
---------
GET  /healthz                                — process-liveness probe
POST {webhook_path}                          — Bitbucket webhook, default domain
POST {webhook_path}/{domain}                 — Bitbucket webhook, explicit domain
POST {github_webhook_path}                   — GitHub webhook, default domain
POST {github_webhook_path}/{domain}          — GitHub webhook, explicit domain

The URL path's optional `{domain}` segment selects which focus prompt the
reviewer applies — e.g. `/webhook/github/ml` reviews with the ML/ASR
priorities, `/webhook/bitbucket/data-eng` with the pipeline priorities.
Each repo's webhook config points at the right URL, so the domain
travels with the request rather than living in a server-side env map.

Each enabled provider has its own HMAC secret + IP allowlist. They share
the worker pool. Handlers verify, parse, enqueue, return 202 in ms; the
heavy work (clone + Claude) runs on the worker so the forge doesn't time
out its delivery (≈10s budget).
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from bugbot.config import Settings, load_settings
from bugbot.libs.logging import configure_logging, get_logger
from bugbot.server.auth import (
    BitbucketIPAllowlist,
    GitHubIPAllowlist,
    client_ip,
    verify_hmac_signature,
)
from bugbot.server.webhook import (
    KNOWN_EVENTS,
    WebhookParseError,
    parse_webhook,
)
from bugbot.server.webhook_github import parse_github_webhook
from bugbot.server.worker import ReviewJob, ReviewWorker
from bugbot.services.review import is_valid_domain

log = get_logger("server")


def _resolve_domain(raw: str | None, default: str) -> str:
    """URL-path domain → validated domain string.

    None / empty → default (the bare `/webhook/{provider}` route).
    Unknown → raise 400 so a typo in a repo's webhook URL is loud at
    delivery time rather than silently using the wrong prompt.
    """
    if raw in (None, ""):
        return default
    if not is_valid_domain(raw):  # type: ignore[arg-type]
        raise HTTPException(
            status_code=400,
            detail=f"unknown review domain {raw!r}",
        )
    return raw  # type: ignore[return-value]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        log.info("shutting down review worker")
        app.state.worker.shutdown(wait=False)

    app = FastAPI(title="bugbot", version="0.1.0", docs_url=None, redoc_url=None,
                  lifespan=_lifespan)
    app.state.settings = settings
    app.state.worker = ReviewWorker(settings)
    app.state.ip_allow_bitbucket = BitbucketIPAllowlist(
        refresh_seconds=settings.webhook_ip_cache_seconds,
    )
    app.state.ip_allow_github = GitHubIPAllowlist(
        refresh_seconds=settings.webhook_ip_cache_seconds,
    )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "status": "ok",
            "providers": {
                "bitbucket": settings.bitbucket_enabled,
                "github": settings.github_enabled,
            },
        }

    # ---- Bitbucket handler (shared by base + /{domain} routes) -------
    async def _handle_bitbucket(
        request: Request,
        domain: str | None,
        x_event_key: str | None,
        x_hub_signature: str | None,
        x_forwarded_for: str | None,
    ) -> JSONResponse:
        s: Settings = request.app.state.settings
        worker: ReviewWorker = request.app.state.worker
        ip_allow: BitbucketIPAllowlist = request.app.state.ip_allow_bitbucket

        if not s.bitbucket_enabled:
            raise HTTPException(status_code=503, detail="bitbucket not configured")

        # 1. IP allowlist
        if s.webhook_enforce_ip_allowlist:
            peer = request.client.host if request.client else ""
            src = client_ip(
                peer=peer,
                forwarded_for=x_forwarded_for,
                trust_forwarded=s.trust_forwarded_for,
            )
            if not ip_allow.is_allowed(src):
                log.warning("rejecting bitbucket webhook from non-Atlassian IP {}", src)
                raise HTTPException(status_code=403, detail="ip not allowed")

        # 2. HMAC
        body = await request.body()
        assert s.webhook_secret is not None  # validated at startup
        ok = verify_hmac_signature(
            body=body,
            header=x_hub_signature,
            secret=s.webhook_secret.get_secret_value(),
        )
        if not ok:
            log.warning("rejecting bitbucket webhook with bad/missing signature event={}",
                        x_event_key)
            raise HTTPException(status_code=401, detail="bad signature")

        # 3. Domain validation. Done after auth so external probes don't
        # learn the URL routing structure from a 400 vs 403 split — but
        # before parse so a typo'd URL never enqueues a job.
        resolved_domain = _resolve_domain(domain, s.default_domain)

        # 4. Parse
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="malformed JSON body")

        try:
            event = parse_webhook(event_key=x_event_key, payload=payload)
        except WebhookParseError as exc:
            log.info("ignoring unparseable bitbucket webhook: {}", exc)
            return JSONResponse({"status": "ignored"}, status_code=204)

        if not event.should_review:
            if event.event_key in KNOWN_EVENTS:
                log.info("ignoring non-trigger event {} ({}/{}/#{})",
                         event.event_key, event.workspace,
                         event.repo_slug, event.pr_id)
            else:
                log.info("unknown event key {}", event.event_key)
            return JSONResponse({"status": "ignored"}, status_code=204)

        # 4. Enqueue
        job = ReviewJob(
            workspace=event.workspace,
            repo_slug=event.repo_slug,
            pr_id=event.pr_id,
            provider="bitbucket",
            domain=resolved_domain,
        )
        accepted = worker.submit(job)
        log.info(
            "{} bitbucket review {}/{}#{} (event={}, actor={}, domain={})",
            "accepted" if accepted else "deduped",
            event.workspace, event.repo_slug, event.pr_id,
            event.event_key, event.actor, resolved_domain,
        )
        return JSONResponse(
            {"status": "accepted" if accepted else "deduped",
             "pr_id": event.pr_id, "domain": resolved_domain},
            status_code=202,
        )

    @app.post(settings.webhook_path, status_code=status.HTTP_202_ACCEPTED)
    async def webhook_bitbucket_base(
        request: Request,
        x_event_key: str | None = Header(default=None),
        x_hub_signature: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> JSONResponse:
        return await _handle_bitbucket(
            request, None, x_event_key, x_hub_signature, x_forwarded_for,
        )

    @app.post(
        settings.webhook_path + "/{domain}",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def webhook_bitbucket_domain(
        request: Request,
        domain: str,
        x_event_key: str | None = Header(default=None),
        x_hub_signature: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> JSONResponse:
        return await _handle_bitbucket(
            request, domain, x_event_key, x_hub_signature, x_forwarded_for,
        )

    # ---- GitHub handler (shared by base + /{domain} routes) ----------
    async def _handle_github(
        request: Request,
        domain: str | None,
        x_github_event: str | None,
        x_hub_signature_256: str | None,
        x_forwarded_for: str | None,
    ) -> JSONResponse:
        s: Settings = request.app.state.settings
        worker: ReviewWorker = request.app.state.worker
        ip_allow: GitHubIPAllowlist = request.app.state.ip_allow_github

        if not s.github_enabled:
            raise HTTPException(status_code=503, detail="github not configured")

        # 1. IP allowlist
        if s.webhook_enforce_ip_allowlist:
            peer = request.client.host if request.client else ""
            src = client_ip(
                peer=peer,
                forwarded_for=x_forwarded_for,
                trust_forwarded=s.trust_forwarded_for,
            )
            if not ip_allow.is_allowed(src):
                log.warning("rejecting github webhook from non-GitHub IP {}", src)
                raise HTTPException(status_code=403, detail="ip not allowed")

        # 2. HMAC
        body = await request.body()
        assert s.github_webhook_secret is not None
        ok = verify_hmac_signature(
            body=body,
            header=x_hub_signature_256,
            secret=s.github_webhook_secret.get_secret_value(),
        )
        if not ok:
            log.warning("rejecting github webhook with bad/missing signature event={}",
                        x_github_event)
            raise HTTPException(status_code=401, detail="bad signature")

        if x_github_event == "ping":
            return JSONResponse({"status": "pong"}, status_code=204)

        # 3. Domain validation (after auth — see bitbucket handler).
        resolved_domain = _resolve_domain(domain, s.default_domain)

        # 4. Parse
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="malformed JSON body")

        try:
            event = parse_github_webhook(
                event_header=x_github_event, payload=payload,
            )
        except WebhookParseError as exc:
            log.info("ignoring unparseable github webhook: {}", exc)
            return JSONResponse({"status": "ignored"}, status_code=204)

        if not event.should_review:
            log.info("ignoring non-trigger github event {} ({}/{}/#{})",
                     event.event_key, event.workspace,
                     event.repo_slug, event.pr_id)
            return JSONResponse({"status": "ignored"}, status_code=204)

        # 4. Enqueue
        job = ReviewJob(
            workspace=event.workspace,
            repo_slug=event.repo_slug,
            pr_id=event.pr_id,
            provider="github",
            domain=resolved_domain,
        )
        accepted = worker.submit(job)
        log.info(
            "{} github review {}/{}#{} (event={}, actor={}, domain={})",
            "accepted" if accepted else "deduped",
            event.workspace, event.repo_slug, event.pr_id,
            event.event_key, event.actor, resolved_domain,
        )
        return JSONResponse(
            {"status": "accepted" if accepted else "deduped",
             "pr_id": event.pr_id, "domain": resolved_domain},
            status_code=202,
        )

    @app.post(settings.github_webhook_path, status_code=status.HTTP_202_ACCEPTED)
    async def webhook_github_base(
        request: Request,
        x_github_event: str | None = Header(default=None),
        x_hub_signature_256: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> JSONResponse:
        return await _handle_github(
            request, None, x_github_event, x_hub_signature_256, x_forwarded_for,
        )

    @app.post(
        settings.github_webhook_path + "/{domain}",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def webhook_github_domain(
        request: Request,
        domain: str,
        x_github_event: str | None = Header(default=None),
        x_hub_signature_256: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> JSONResponse:
        return await _handle_github(
            request, domain, x_github_event, x_hub_signature_256, x_forwarded_for,
        )

    return app


# Use the uvicorn factory pattern (`--factory`) so importing this module
# in tests or other tools does NOT trigger settings load at import time.
# See cli/main.py:serve and Dockerfile CMD.
