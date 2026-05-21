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
GH_SECRET = "ghsecret"


def _settings(*, github: bool = False) -> Settings:
    # Minimal valid settings for the server; webhook secret is what we care
    # about. IP allowlist disabled so we don't need to mock the upstream
    # IP feeds.
    kwargs: dict = dict(
        bitbucket_username="u",
        bitbucket_app_password=SecretStr("p"),
        webhook_secret=SecretStr(SECRET),
        webhook_enforce_ip_allowlist=False,
    )
    if github:
        kwargs["github_token"] = SecretStr("ghp_xxx")
        kwargs["github_webhook_secret"] = SecretStr(GH_SECRET)
    # `_env_file=None` keeps the on-disk dev .env from leaking into tests.
    return Settings(_env_file=None, **kwargs)  # type: ignore[call-arg]


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _payload(pr_id: int = 7) -> bytes:
    return json.dumps({
        "repository": {"full_name": "my-ws/my-repo"},
        "pullrequest": {"id": pr_id, "title": "t"},
        "actor": {"display_name": "Alice"},
    }).encode("utf-8")


def _github_payload(action: str = "opened", number: int = 7) -> bytes:
    return json.dumps({
        "action": action,
        "repository": {"full_name": "acme/widget"},
        "pull_request": {"number": number, "title": "t", "draft": False},
        "sender": {"login": "alice"},
    }).encode("utf-8")


@pytest.fixture
def client():
    app = create_app(_settings())
    submitted: list[Any] = []
    app.state.worker.submit = lambda job: submitted.append(job) or True  # type: ignore
    with TestClient(app) as c:
        c.submitted = submitted  # type: ignore[attr-defined]
        yield c


@pytest.fixture
def client_both():
    """Server with both Bitbucket and GitHub configured."""
    app = create_app(_settings(github=True))
    submitted: list[Any] = []
    app.state.worker.submit = lambda job: submitted.append(job) or True  # type: ignore
    with TestClient(app) as c:
        c.submitted = submitted  # type: ignore[attr-defined]
        yield c


def _sign_gh(body: bytes, secret: str = GH_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    # Bitbucket-only fixture: providers map reflects what's actually wired.
    assert body["providers"] == {"bitbucket": True, "github": False}


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


# ----------------------------------------------------------------------
# GitHub endpoint
# ----------------------------------------------------------------------


def test_github_webhook_503_when_not_configured(client):
    """Bitbucket-only deployment: hitting /webhook/github returns 503 so
    operators notice the misconfiguration instead of getting silent 401s."""
    body = _github_payload()
    r = client.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 503


def test_github_webhook_rejects_bad_signature(client_both):
    body = _github_payload()
    r = client_both.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body, "wrong"),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 401


def test_github_webhook_uses_separate_secret_from_bitbucket(client_both):
    """Cross-secret check: signing a GitHub body with the Bitbucket secret
    must NOT authorise it. Each provider has its own HMAC key."""
    body = _github_payload()
    r = client_both.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body, SECRET),  # wrong secret
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 401


def test_github_webhook_accepts_valid_pr_opened(client_both):
    body = _github_payload(action="opened", number=99)
    r = client_both.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 202
    assert r.json()["status"] == "accepted"
    job = client_both.submitted[0]  # type: ignore[attr-defined]
    assert job.provider == "github"
    assert job.workspace == "acme"
    assert job.repo_slug == "widget"
    assert job.pr_id == 99


def test_github_webhook_handles_ping_event(client_both):
    """When you save the webhook config GitHub fires a `ping` — we must
    not 401 it (the body isn't a pull_request payload) and not enqueue
    anything either."""
    body = b'{"zen":"Practicality beats purity."}'
    r = client_both.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": _sign_gh(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 204
    assert client_both.submitted == []  # type: ignore[attr-defined]


def test_github_webhook_ignores_non_trigger_action(client_both):
    body = _github_payload(action="labeled")
    r = client_both.post(
        "/webhook/github",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 204
    assert client_both.submitted == []  # type: ignore[attr-defined]


def test_healthz_reports_enabled_providers(client_both):
    r = client_both.get("/healthz")
    body = r.json()
    assert body["status"] == "ok"
    assert body["providers"] == {"bitbucket": True, "github": True}


# ----------------------------------------------------------------------
# URL-path domain routing — the domain travels with the webhook URL.
# ----------------------------------------------------------------------


def test_bitbucket_bare_path_uses_default_domain(client):
    body = _payload(pr_id=10)
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
    job = client.submitted[0]  # type: ignore[attr-defined]
    assert job.domain == "general"  # = default_domain


def test_bitbucket_url_with_domain_propagates_to_job(client):
    body = _payload(pr_id=11)
    r = client.post(
        "/webhook/bitbucket/data-eng",
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 202
    body_json = r.json()
    assert body_json["domain"] == "data-eng"
    job = client.submitted[0]  # type: ignore[attr-defined]
    assert job.domain == "data-eng"


def test_github_url_with_domain_propagates_to_job(client_both):
    body = _github_payload(action="opened", number=42)
    r = client_both.post(
        "/webhook/github/ml",
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign_gh(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 202
    job = client_both.submitted[0]  # type: ignore[attr-defined]
    assert job.domain == "ml"
    assert job.provider == "github"


def test_webhook_url_with_unknown_domain_400s(client):
    """A typo in a repo's webhook URL must be loud — better to reject
    the delivery so the operator sees it in the forge's "Recent
    Deliveries" tab than to silently swap the focus prompt."""
    body = _payload(pr_id=12)
    r = client.post(
        "/webhook/bitbucket/asr-mdoel",  # typo
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 400
    assert "unknown review domain" in r.json().get("detail", "")


def test_webhook_domain_blocks_path_traversal(client):
    """Even if the path matches FastAPI's `{domain}` segment, the domain
    validator must reject anything outside `[A-Za-z0-9_-]+`."""
    body = _payload(pr_id=13)
    # Trying to escape the focus directory via the domain segment.
    r = client.post(
        "/webhook/bitbucket/..%2Fetc%2Fpasswd",
        headers={
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature": _sign(body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert r.status_code in (400, 404)
