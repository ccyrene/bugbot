"""URL/payload shape tests for the GitHub client. Like the Bitbucket
client tests we never hit the real API — respx intercepts httpx calls
and we assert exactly what would have been sent."""

import httpx
import pytest

try:
    import respx
except ImportError:  # pragma: no cover
    respx = None

from bugbot.clients._provider import InlineComment
from bugbot.clients.github import GitHubClient, GitHubError

pytestmark = pytest.mark.skipif(respx is None, reason="respx not installed")


def _client() -> GitHubClient:
    return GitHubClient(token="ghp_token", owner="acme", repo="thing")


@respx.mock
def test_uses_bearer_auth_and_api_version_header():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={
            "number": 1, "title": "t", "body": "",
            "head": {"ref": "f", "sha": "a"},
            "base": {"ref": "m", "sha": "b"},
            "user": {"login": "x"},
        })

    respx.get("https://api.github.com/repos/acme/thing/pulls/1").mock(side_effect=handler)
    _client().get_pull_request(1)
    h = captured["headers"]
    # Bearer auth — GitHub does NOT accept Basic auth with PAT on REST.
    assert h.get("authorization") == "Bearer ghp_token"
    # Explicit API version pin keeps us forward-compatible.
    assert h.get("x-github-api-version") == "2022-11-28"
    # Standard `Accept` for JSON responses.
    assert "application/vnd.github+json" in (h.get("accept") or "")


@respx.mock
def test_get_pull_request_url_and_parsing():
    route = respx.get("https://api.github.com/repos/acme/thing/pulls/42").respond(
        json={
            "number": 42,
            "title": "Add thing",
            "body": "does the thing",
            "head": {"ref": "feature", "sha": "abc"},
            "base": {"ref": "main", "sha": "def"},
            "user": {"login": "alice"},
        },
    )
    pr = _client().get_pull_request(42)
    assert route.called
    assert pr.id == 42
    assert pr.title == "Add thing"
    assert pr.source_branch == "feature"
    assert pr.destination_branch == "main"
    assert pr.source_commit == "abc"
    assert pr.author == "alice"


@respx.mock
def test_get_diff_requests_diff_media_type():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["accept"] = request.headers.get("accept")
        return httpx.Response(200, text="diff --git a/x b/x\n+hello\n")

    respx.get("https://api.github.com/repos/acme/thing/pulls/42").mock(side_effect=handler)
    out = _client().get_pull_request_diff(42)
    # The bit that matters: we asked GitHub for the diff representation
    # of the PR, not the JSON one. Otherwise we'd parse a JSON envelope
    # as if it were a unified diff.
    assert captured["accept"] == "application/vnd.github.v3.diff"
    assert "diff --git" in out


@respx.mock
def test_post_summary_comment_payload_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    # Summary goes to /issues/{n}/comments (PRs are issues on GitHub).
    respx.post(
        "https://api.github.com/repos/acme/thing/issues/42/comments"
    ).mock(side_effect=handler)

    _client().post_summary_comment(42, "summary body")
    assert captured["json"] == {"body": "summary body"}


@respx.mock
def test_post_inline_comment_requires_commit_id():
    # No respx route — we expect to raise before the request fires.
    with pytest.raises(GitHubError):
        _client().post_inline_comment(
            42, InlineComment(file="x.py", line=1, body="b"),
        )


@respx.mock
def test_post_inline_comment_payload_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    respx.post(
        "https://api.github.com/repos/acme/thing/pulls/42/comments"
    ).mock(side_effect=handler)

    _client().post_inline_comment(
        42,
        InlineComment(file="src/app.py", line=12, body="hi", commit_id="sha-head"),
    )
    payload = captured["json"]
    assert payload["body"] == "hi"
    assert payload["path"] == "src/app.py"
    assert payload["line"] == 12
    # commit_id is GitHub-mandatory — without it the API 422s.
    assert payload["commit_id"] == "sha-head"
    # side=RIGHT anchors on the post-change line, matching the `+` line
    # numbers our reviewer emits.
    assert payload["side"] == "RIGHT"
    # Single-line comment must NOT include start_line / start_side — if
    # we sent them with start_line == line, GitHub responds 422.
    assert "start_line" not in payload
    assert "start_side" not in payload


@respx.mock
def test_post_inline_comment_multiline_suggestion_includes_range():
    """Multi-line ```suggestion blocks require GitHub's range fields:
    start_line + start_side. Without both, the API rejects with 422."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    respx.post(
        "https://api.github.com/repos/acme/thing/pulls/42/comments"
    ).mock(side_effect=handler)

    _client().post_inline_comment(
        42,
        InlineComment(
            file="src/app.py", line=14, start_line=12,
            body="hi", commit_id="sha-head",
        ),
    )
    payload = captured["json"]
    assert payload["line"] == 14
    assert payload["start_line"] == 12
    assert payload["start_side"] == "RIGHT"


@respx.mock
def test_post_inline_comment_ignores_start_line_equal_to_line():
    """start_line == line is a single-line comment. Sending the range
    fields anyway would be a no-op at best and a 422 at worst — make
    sure the client treats them as absent."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        captured["json"] = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1})

    respx.post(
        "https://api.github.com/repos/acme/thing/pulls/42/comments"
    ).mock(side_effect=handler)

    _client().post_inline_comment(
        42,
        InlineComment(
            file="x.py", line=5, start_line=5,
            body="b", commit_id="sha",
        ),
    )
    payload = captured["json"]
    assert "start_line" not in payload
    assert "start_side" not in payload


@respx.mock
def test_list_comments_merges_inline_and_issue():
    inline = [
        {"id": 100, "path": "a.py", "line": 3, "body": "inline-a"},
        {"id": 101, "path": "a.py", "line": 5, "body": "inline-b"},
    ]
    issue = [
        {"id": 200, "body": "top-level summary"},
    ]
    respx.get(
        "https://api.github.com/repos/acme/thing/pulls/42/comments"
    ).respond(json=inline)
    respx.get(
        "https://api.github.com/repos/acme/thing/issues/42/comments"
    ).respond(json=issue)

    out = _client().list_comments(42)
    ids = [c.id for c in out]
    assert sorted(ids) == [100, 101, 200]
    # The summary comment has no file/line — important for idempotency
    # so we don't try to match it against a `(file, line)` pair.
    summary = next(c for c in out if c.id == 200)
    assert summary.file is None
    assert summary.line is None


@respx.mock
def test_paginate_follows_link_header_rel_next():
    # Why url__regex + iterated side_effect instead of two `respx.get`
    # calls for the same path: respx matches by URL prefix and the second
    # registration would shadow the first, so when the client follows the
    # `next` link it would hit the same response again → infinite loop →
    # OOM. Whoever has been bitten by this before, write it down.
    page1 = [{"id": 1, "path": "a.py", "line": 1, "body": "a"}]
    page2 = [{"id": 2, "path": "a.py", "line": 2, "body": "b"}]
    next_url = "https://api.github.com/repos/acme/thing/pulls/42/comments?page=2"
    last_url = "https://api.github.com/repos/acme/thing/pulls/42/comments?page=9"

    responses = iter([
        httpx.Response(
            200,
            json=page1,
            headers={
                "Link": f'<{next_url}>; rel="next", <{last_url}>; rel="last"',
            },
        ),
        httpx.Response(200, json=page2),
    ])
    respx.get(
        url__regex=r"https://api\.github\.com/repos/acme/thing/pulls/42/comments.*"
    ).mock(side_effect=lambda _request: next(responses))
    respx.get(
        "https://api.github.com/repos/acme/thing/issues/42/comments"
    ).respond(json=[])

    out = _client().list_comments(42)
    assert sorted(c.id for c in out) == [1, 2]


@respx.mock
def test_4xx_raises_github_error_with_redacted_body():
    # Body contains a fake AWS key — must NOT appear in the raised error.
    respx.get(
        "https://api.github.com/repos/acme/thing/pulls/42"
    ).respond(status_code=403, text='{"error":"AKIAIOSFODNN7EXAMPLE"}')

    with pytest.raises(GitHubError) as ei:
        _client().get_pull_request(42)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(ei.value)
    assert "REDACTED" in str(ei.value)
