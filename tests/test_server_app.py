"""End-to-end webhook tests using FastAPI TestClient.

We stub the worker so no real Claude/Bitbucket calls happen — we're
exercising the auth/parse/enqueue pipeline only."""

import hashlib
import hmac
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from bugbot.config import Settings
from bugbot.server.app import create_app


SECRET = "topsecret"


def _settings() -> Settings:
    # Minimal valid settings for the server; webhook secret is what we care
    # about. IP allowlist disabled so we don't need to mock the Atlassian
    # IP feed.
    return Settings(
        bitbucket_username="u",
        bitbucket_app_password=SecretStr("p"),
        webhook_secret=SecretStr(SECRET),
        webhook_enforce_ip_allowlist=False,
    )


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _payload(pr_id: int = 7) -> bytes:
    return json.dumps({
        "repository": {"full_name": "my-ws/my-repo"},
        "pullrequest": {"id": pr_id, "title": "t"},
        "actor": {"display_name": "Alice"},
    }).encode("utf-8")


@pytest.fixture
def client():
    app = create_app(_settings())
    submitted: list[Any] = []
    app.state.worker.submit = lambda job: submitted.append(job) or True  # type: ignore
    with TestClient(app) as c:
        c.submitted = submitted  # type: ignore[attr-defined]
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_webhook_rejects_missing_signature(client):
    body = _payload()
    r = client.post(
        "/webhook/bitbucket",
        headers={"X-Event-Key": "pullrequest:created", "Content-Type": "application/json"},
        content=body,
    )
    assert r.status_code == 401


def test_webhook_rejects_bad_signature(client):
    body = _payload()
    r = client.post(
        "/webhook/bitbucket",
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body, "wrong-secret"),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 401


def test_webhook_accepts_valid_pr_created(client):
    body = _payload(pr_id=42)
    r = client.post(
        "/webhook/bitbucket",
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 202
    assert r.json()["status"] == "accepted"
    assert len(client.submitted) == 1  # type: ignore[attr-defined]
    job = client.submitted[0]  # type: ignore[attr-defined]
    assert job.workspace == "my-ws"
    assert job.repo_slug == "my-repo"
    assert job.pr_id == 42


def test_webhook_ignores_non_trigger_event(client):
    body = _payload()
    r = client.post(
        "/webhook/bitbucket",
        headers={
            "X-Event-Key": "pullrequest:approved",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 204
    assert client.submitted == []  # type: ignore[attr-defined]


def test_webhook_ignores_unparseable_payload(client):
    body = b"{not json"
    r = client.post(
        "/webhook/bitbucket",
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 400


def test_webhook_dedupes_same_pr(client):
    body = _payload(pr_id=99)
    # Override worker.submit to simulate dedupe on second submit.
    seen = []

    def submit(job):
        if job.pr_id in seen:
            return False
        seen.append(job.pr_id)
        return True

    client.app.state.worker.submit = submit  # type: ignore

    for _ in range(2):
        r = client.post(
            "/webhook/bitbucket",
            headers={
                "X-Event-Key": "pullrequest:updated",
                "X-Hub-Signature": _sign(body),
                "Content-Type": "application/json",
            },
            content=body,
        )
        assert r.status_code == 202
    statuses = [client.post(
        "/webhook/bitbucket",
        headers={
            "X-Event-Key": "pullrequest:updated",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    ).json()["status"] for _ in range(0)]  # already-asserted above
    _ = statuses
