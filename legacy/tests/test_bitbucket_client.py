"""URL/payload shape tests for the Bitbucket client. We don't hit the real
API — respx intercepts httpx calls and lets us assert what would have been
sent. This is the most security-relevant client (it has write scope), so
we lock the request shape down with tests."""

import httpx
import pytest

try:
    import respx
except ImportError:  # pragma: no cover
    respx = None

from bugbot.clients.bitbucket import BitbucketClient, InlineComment

pytestmark = pytest.mark.skipif(respx is None, reason="respx not installed")


def _client() -> BitbucketClient:
    return BitbucketClient(
        username="user",
        app_password="pw",
        workspace="my-ws",
        repo_slug="my-repo",
    )


@respx.mock
def test_x_token_auth_username_switches_to_bearer():
    """Repository/Workspace Access Tokens (ATCTT3…) require Bearer; the
    legacy `x-token-auth` basic-auth username form was deprecated for the
    v2 REST API. When the caller passes that sentinel, we MUST send a
    Bearer header, not a Basic Authorization header."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={
            "id": 1, "title": "t", "description": "",
            "source": {"branch": {"name": "f"}, "commit": {"hash": "a"}},
            "destination": {"branch": {"name": "m"}, "commit": {"hash": "b"}},
            "author": {"display_name": "x"},
        })

    respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/1"
    ).mock(side_effect=handler)

    BitbucketClient(
        username="x-token-auth", app_password="ATCTT3xyz",
        workspace="my-ws", repo_slug="my-repo",
    ).get_pull_request(1)

    auth_header = captured["headers"].get("authorization") or ""
    assert auth_header == "Bearer ATCTT3xyz"


@respx.mock
def test_non_sentinel_username_uses_basic_auth():
    """For App Passwords and Atlassian API tokens, basic auth with the
    user's email is the right move."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={
            "id": 1, "title": "t", "description": "",
            "source": {"branch": {"name": "f"}, "commit": {"hash": "a"}},
            "destination": {"branch": {"name": "m"}, "commit": {"hash": "b"}},
            "author": {"display_name": "x"},
        })

    respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/1"
    ).mock(side_effect=handler)

    BitbucketClient(
        username="me@example.com", app_password="ATATT3xyz",
        workspace="my-ws", repo_slug="my-repo",
    ).get_pull_request(1)

    # httpx encodes basic auth: "Basic base64(user:pass)"
    import base64
    auth_header = captured["headers"].get("authorization") or ""
    assert auth_header.startswith("Basic ")
    decoded = base64.b64decode(auth_header.removeprefix("Basic ")).decode()
    assert decoded == "me@example.com:ATATT3xyz"


@respx.mock
def test_get_pull_request_url_and_parsing():
    route = respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42"
    ).respond(
        json={
            "id": 42,
            "title": "Add thing",
            "description": "does the thing",
            "source": {"branch": {"name": "feature"}, "commit": {"hash": "abc"}},
            "destination": {"branch": {"name": "main"}, "commit": {"hash": "def"}},
            "author": {"display_name": "Alice"},
        },
    )
    pr = _client().get_pull_request(42)
    assert route.called
    assert pr.title == "Add thing"
    assert pr.source_branch == "feature"
    assert pr.destination_branch == "main"
    assert pr.author == "Alice"


@respx.mock
def test_get_diff_returns_raw_text():
    respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42/diff"
    ).respond(text="diff --git a/x b/x\n")
    assert _client().get_pull_request_diff(42).startswith("diff --git")


@respx.mock
def test_get_diff_follows_302_redirect():
    """Bitbucket Cloud responds to /pullrequests/{id}/diff with a 302 that
    points at the canonical commit-pair diff URL. We MUST follow it or we'd
    silently treat empty 302 bodies as 'nothing to review'."""
    canonical = (
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/diff/"
        "my-ws/my-repo:aaa..bbb?from_pullrequest_id=42"
    )
    respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42/diff"
    ).respond(
        status_code=302,
        headers={"Location": canonical},
        text="",
    )
    respx.get(canonical).respond(text="diff --git a/x b/x\n+hello\n")

    out = _client().get_pull_request_diff(42)
    assert "diff --git" in out
    assert "+hello" in out


@respx.mock
def test_post_inline_comment_payload_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    respx.post(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42/comments"
    ).mock(side_effect=handler)

    _client().post_inline_comment(
        42, InlineComment(file="src/app.py", line=12, body="hello"),
    )
    assert captured["json"] == {
        "content": {"raw": "hello"},
        "inline": {"path": "src/app.py", "to": 12},
    }


@respx.mock
def test_post_summary_comment_payload_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    respx.post(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42/comments"
    ).mock(side_effect=handler)

    _client().post_summary_comment(42, "summary body")
    assert captured["json"] == {"content": {"raw": "summary body"}}
    # Crucially: NO `inline` key, so Bitbucket treats it as top-level.
    assert "inline" not in captured["json"]


@respx.mock
def test_list_comments_paginates_and_skips_deleted():
    page1 = {
        "values": [
            {"id": 1, "content": {"raw": "a"}, "inline": {"path": "f.py", "to": 1}},
            {"id": 2, "deleted": True, "content": {"raw": "gone"}},
        ],
        "next": "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42/comments?page=2",
    }
    page2 = {"values": [{"id": 3, "content": {"raw": "c"}}]}
    responses = iter([
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ])
    respx.get(
        url__regex=r"https://api\.bitbucket\.org/2\.0/repositories/my-ws/my-repo/pullrequests/42/comments.*"
    ).mock(side_effect=lambda _request: next(responses))
    out = _client().list_comments(42)
    assert [c.id for c in out] == [1, 3]


@respx.mock
def test_4xx_raises_bitbucket_error_with_redacted_body():
    from bugbot.clients.bitbucket import BitbucketError

    # Body contains a fake AWS key — must not appear in the raised error.
    respx.get(
        "https://api.bitbucket.org/2.0/repositories/my-ws/my-repo/pullrequests/42"
    ).respond(status_code=403, text='{"error":"AKIAIOSFODNN7EXAMPLE"}')

    with pytest.raises(BitbucketError) as ei:
        _client().get_pull_request(42)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(ei.value)
    assert "REDACTED" in str(ei.value)
