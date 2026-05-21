"""GitHub REST v3 PR client.

Mirrors the Bitbucket client's surface so the orchestrator can be
provider-agnostic. Implements `PullRequestProvider` from `_provider.py`.

Auth: Bearer with a fine-grained or classic PAT. We treat them identically
on the wire; the difference is on the GitHub side (scope granularity).

Required token permissions for a fine-grained PAT:
  * Contents:        Read
  * Pull requests:   Read & Write
  * Metadata:        Read (implicit)

Classic PAT alternative: scope `repo` (also grants more than we need).

Inline ("review") comment endpoint
----------------------------------
GitHub requires `commit_id` on every inline comment — the SHA the comment
is anchored to. The orchestrator passes `PullRequest.source_commit`
through the optional `commit_id` field on `InlineComment`.

API reference:
  https://docs.github.com/en/rest/pulls
  https://docs.github.com/en/rest/issues/comments
"""

from __future__ import annotations

import re
from typing import Any, Iterator

import httpx

from bugbot.clients._provider import (
    ExistingComment,
    InlineComment,
    PullRequest,
)
from bugbot.libs.logging import get_logger
from bugbot.libs.redact import redact

log = get_logger("github")


__all__ = ["GitHubClient", "GitHubError"]


class GitHubError(RuntimeError):
    pass


_CLONE_HOST = "github.com"
# Git-over-HTTPS basic-auth URL form GitHub still accepts; the actual auth
# token goes in the password slot.
_GIT_CLONE_USERNAME = "x-access-token"


class GitHubClient:
    """Minimal REST v3 client — PR metadata, diff, comments.

    `owner` and `repo` map to Bitbucket's `workspace`/`repo_slug`. We
    keep the property names aligned with `BitbucketClient` so the
    Reviewer doesn't need to branch.
    """

    def __init__(
        self,
        *,
        token: str,
        owner: str,
        repo: str,
        base_url: str = "https://api.github.com",
        timeout: float = 60.0,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bugbot/0.1",
        }
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            # GitHub diff endpoint can issue redirects (e.g. legacy URLs).
            follow_redirects=True,
        )
        self._owner = owner
        self._repo = repo
        self._token = token

    # ---- PullRequestProvider surface --------------------------------------
    @property
    def workspace(self) -> str:
        return self._owner

    @property
    def repo_slug(self) -> str:
        return self._repo

    @property
    def username(self) -> str:
        # Used by the git clone helper to build the basic-auth URL.
        return _GIT_CLONE_USERNAME

    @property
    def app_password(self) -> str:
        return self._token

    @property
    def clone_host(self) -> str:
        return _CLONE_HOST

    # ---- internal ---------------------------------------------------------
    def _repo_path(self, suffix: str) -> str:
        return f"/repos/{self._owner}/{self._repo}{suffix}"

    def _raise(self, resp: httpx.Response, action: str) -> None:
        if resp.status_code >= 400:
            raise GitHubError(
                f"GitHub {action} failed ({resp.status_code}): "
                f"{redact(resp.text)[:500]}"
            )

    # GitHub paginates via Link header (RFC 5988). Sample:
    #   Link: <https://api.github.com/…?page=2>; rel="next", <…>; rel="last"
    _NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

    def _paginate(
        self, url: str, params: dict[str, Any] | None = None
    ) -> Iterator[dict]:
        next_url: str | None = url
        next_params = params or {"per_page": 100}
        while next_url:
            resp = self._client.get(next_url, params=next_params)
            self._raise(resp, action=f"GET {next_url}")
            data = resp.json()
            # GitHub list endpoints return a bare JSON array, not an
            # envelope with .values like Bitbucket.
            if isinstance(data, list):
                yield from data
            elif isinstance(data, dict) and "items" in data:
                yield from data.get("items") or []
            link = resp.headers.get("link") or ""
            m = self._NEXT_LINK_RE.search(link)
            next_url = m.group(1) if m else None
            next_params = None  # absolute URL carries its own params

    # ---- public -----------------------------------------------------------
    def get_pull_request(self, pr_id: int) -> PullRequest:
        resp = self._client.get(self._repo_path(f"/pulls/{pr_id}"))
        self._raise(resp, action="get_pull_request")
        data = resp.json()
        return PullRequest(
            id=int(data["number"]),
            title=data.get("title") or "",
            description=data.get("body") or "",
            source_branch=(data.get("head") or {}).get("ref") or "",
            destination_branch=(data.get("base") or {}).get("ref") or "",
            source_commit=(data.get("head") or {}).get("sha") or "",
            destination_commit=(data.get("base") or {}).get("sha") or "",
            author=((data.get("user") or {}).get("login")) or "unknown",
        )

    def get_pull_request_diff(self, pr_id: int) -> str:
        # Content-negotiation: ask for the unified diff representation of
        # the same PR resource. Body comes back as text, not JSON.
        resp = self._client.get(
            self._repo_path(f"/pulls/{pr_id}"),
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        self._raise(resp, action="get_pull_request_diff")
        return resp.text

    def list_comments(self, pr_id: int) -> list[ExistingComment]:
        """Combine *issue* comments (top-level) + *review* comments (inline).

        Both feed into the idempotency check — without the issue-comments
        leg we'd re-post the summary on every webhook fire.
        """
        out: list[ExistingComment] = []

        # 1. Inline review comments — anchored to file/line.
        for c in self._paginate(self._repo_path(f"/pulls/{pr_id}/comments")):
            out.append(ExistingComment(
                id=int(c["id"]),
                file=c.get("path"),
                line=c.get("line") or c.get("original_line"),
                content=c.get("body") or "",
            ))

        # 2. Top-level issue comments — no file/line.
        for c in self._paginate(self._repo_path(f"/issues/{pr_id}/comments")):
            out.append(ExistingComment(
                id=int(c["id"]),
                file=None,
                line=None,
                content=c.get("body") or "",
            ))

        return out

    def post_summary_comment(self, pr_id: int, body: str) -> dict:
        # Summary = issue comment. PRs are issues under the hood on GitHub.
        resp = self._client.post(
            self._repo_path(f"/issues/{pr_id}/comments"),
            json={"body": body},
        )
        self._raise(resp, action="post_summary_comment")
        return resp.json()

    def post_inline_comment(self, pr_id: int, comment: InlineComment) -> dict:
        if not comment.commit_id:
            # The orchestrator should always populate this; if it didn't,
            # fail loudly rather than silently posting a comment that
            # GitHub will reject for the wrong reason.
            raise GitHubError(
                "post_inline_comment requires comment.commit_id (PR head sha)"
            )
        payload = {
            "body": comment.body,
            "commit_id": comment.commit_id,
            "path": comment.file,
            "line": comment.line,
            # Anchor the comment on the post-change side of the diff so the
            # line number matches the `+` lines our reviewer reports.
            "side": "RIGHT",
        }
        resp = self._client.post(
            self._repo_path(f"/pulls/{pr_id}/comments"),
            json=payload,
        )
        self._raise(resp, action="post_inline_comment")
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
