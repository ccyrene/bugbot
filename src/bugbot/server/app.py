"""FastAPI app — single webhook endpoint + healthcheck.

Endpoints
---------
GET  /healthz                 — process-liveness probe
POST <settings.webhook_path>  — Bitbucket webhook receiver

The webhook handler is intentionally small. All it does is:
  1. Verify HMAC signature against the raw body (constant-time).
  2. Verify source IP against Atlassian's allowlist (optional).
  3. Parse the event; ignore anything that isn't a PR create/update.
  4. Enqueue a review job and return 202.

It never blocks on the actual review — that runs in a worker thread so
Bitbucket doesn't time out its webhook delivery (≈10s budget).
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
    client_ip,
    verify_hmac_signature,
)
from bugbot.server.webhook import (
    KNOWN_EVENTS,
    WebhookParseError,
    parse_webhook,
)
from bugbot.server.worker import ReviewJob, ReviewWorker

log = get_logger("server")


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
    app.state.ip_allow = BitbucketIPAllowlist(
        refresh_seconds=settings.webhook_ip_cache_seconds,
    )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post(settings.webhook_path, status_code=status.HTTP_202_ACCEPTED)
    async def webhook(
        request: Request,
        x_event_key: str | None = Header(default=None),
        x_hub_signature: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> JSONResponse:
        s: Settings = request.app.state.settings
        worker: ReviewWorker = request.app.state.worker
        ip_allow: BitbucketIPAllowlist = request.app.state.ip_allow

        # ----- 1. IP allowlist (cheap, fail fast) ------------------------
        if s.webhook_enforce_ip_allowlist:
            peer = request.client.host if request.client else ""
            src = client_ip(
                peer=peer,
                forwarded_for=x_forwarded_for,
                trust_forwarded=s.trust_forwarded_for,
            )
            if not ip_allow.is_allowed(src):
                log.warning("rejecting webhook from non-Atlassian IP {}", src)
                raise HTTPException(status_code=403, detail="ip not allowed")

        # ----- 2. HMAC signature (constant-time) -------------------------
        body = await request.body()
        ok = verify_hmac_signature(
            body=body,
            header=x_hub_signature,
            secret=s.webhook_secret.get_secret_value(),
        )
        if not ok:
            log.warning("rejecting webhook with bad/missing signature event={}",
                        x_event_key)
            raise HTTPException(status_code=401, detail="bad signature")

        # ----- 3. Parse + decide -----------------------------------------
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="malformed JSON body")

        try:
            event = parse_webhook(event_key=x_event_key, payload=payload)
        except WebhookParseError as exc:
            log.info("ignoring unparseable webhook: {}", exc)
            # 204 so Bitbucket marks delivery successful and doesn't retry.
            return JSONResponse({"status": "ignored"}, status_code=204)

        if not event.should_review:
            if event.event_key in KNOWN_EVENTS:
                log.info("ignoring non-trigger event {} ({}/{}/#{})",
                         event.event_key, event.workspace,
                         event.repo_slug, event.pr_id)
            else:
                log.info("unknown event key {}", event.event_key)
            return JSONResponse({"status": "ignored"}, status_code=204)

        # ----- 4. Enqueue ------------------------------------------------
        job = ReviewJob(
            workspace=event.workspace,
            repo_slug=event.repo_slug,
            pr_id=event.pr_id,
        )
        accepted = worker.submit(job)
        log.info(
            "{} review {}/{}#{} (event={}, actor={})",
            "accepted" if accepted else "deduped",
            event.workspace, event.repo_slug, event.pr_id,
            event.event_key, event.actor,
        )
        return JSONResponse(
            {"status": "accepted" if accepted else "deduped", "pr_id": event.pr_id},
            status_code=202,
        )

    return app


# Use the uvicorn factory pattern (`--factory`) so importing this module
# in tests or other tools does NOT trigger settings load at import time.
# See cli/main.py:serve and Dockerfile CMD.
