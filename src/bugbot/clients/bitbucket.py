"""Bitbucket Cloud v2 PR client.

Only the surface we need:
  * fetch PR metadata
  * fetch unified diff
  * fetch list of changed files
  * post a top-level PR comment (summary)
  * post an inline PR comment on a specific file:line
  * list existing PR comments (for idempotency — skip lines we've commented on)

API reference:
  https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pullrequests/
"""

from __future__ import annotations

from typing import Any, Iterator

import httpx

from bugbot.clients._provider import (
    ExistingComment,
    InlineComment,
    PullRequest,
)
from bugbot.libs.logging import get_logger
from bugbot.libs.redact import redact

log = get_logger("bitbucket")


# Re-export so existing imports `from bugbot.clients.bitbucket import …`
# keep working — the shared models live in `_provider` now.
__all__ = [
    "BitbucketClient",
    "BitbucketError",
    "PullRequest",
    "InlineComment",
    "ExistingComment",
]


class BitbucketError(RuntimeError):
    pass


_TOKEN_AUTH_USERNAME = "x-token-auth"
_CLONE_HOST = "bitbucket.org"


class BitbucketClient:
    def __init__(
        self,
        *,
        username: str,
        app_password: str,
        workspace: str,
        repo_slug: str,
        base_url: str = "https://api.bitbucket.org/2.0",
        timeout: float = 60.0,
    ) -> None:
        # Pick auth mode:
        #   * `x-token-auth` sentinel  → Bearer (Repository / Workspace
        #     Access Tokens, format ATCTT3…). Bitbucket Cloud requires
        #     Bearer for these tokens; HTTP basic with `x-token-auth` is
        #     legacy and gets 401 on most v2 endpoints.
        #   * any other username        → HTTP Basic Auth (App Passwords
        #     and Atlassian account API tokens use email as username).
        headers: dict[str, str] = {"Accept": "application/json"}
        auth: tuple[str, str] | None
        if username == _TOKEN_AUTH_USERNAME:
            headers["Authorization"] = f"Bearer {app_password}"
            auth = None
        else:
            auth = (username, app_password)

        self._client = httpx.Client(
            base_url=base_url,
            auth=auth,
            headers=headers,
            timeout=timeout,
            # Bitbucket Cloud's `/pullrequests/{id}/diff` endpoint replies
            # with HTTP 302 → the canonical diff URL keyed on the source/
            # destination commit pair. httpx does NOT follow redirects by
            # default, so without this we'd silently treat the 302 as an
            # empty diff and review nothing.
            follow_redirects=True,
        )
        self._workspace = workspace
        self._repo_slug = repo_slug
        # Stored so the reviewer can hand them to the repo-clone helper
        # without round-tripping through Settings again. The app_password
        # never leaves this process; it's not logged or serialised.
        # Note: git clone over HTTPS still uses `x-token-auth:<token>@…`
        # basic-auth URL form, which Bitbucket continues to accept for git
        # even though REST requires Bearer.
        self._username = username
        self._app_password = app_password

    @property
    def workspace(self) -> str:
        return self._workspace

    @property
    def repo_slug(self) -> str:
        return self._repo_slug

    @property
    def username(self) -> str:
        return self._username

    @property
    def app_password(self) -> str:
        return self._app_password

    @property
    def clone_host(self) -> str:
        return _CLONE_HOST

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------
    def _repo_path(self, suffix: str) -> str:
        return f"/repositories/{self._workspace}/{self._repo_slug}{suffix}"

    def _raise(self, resp: httpx.Response, action: str) -> None:
        if resp.status_code >= 400:
            raise BitbucketError(
                f"Bitbucket {action} failed ({resp.status_code}): {redact(resp.text)[:500]}"
            )

    def _paginate(self, url: str, params: dict[str, Any] | None = None) -> Iterator[dict]:
        next_url: str | None = url
        next_params = params
        while next_url:
            resp = self._client.get(next_url, params=next_params)
            self._raise(resp, action=f"GET {next_url}")
            data = resp.json()
            yield from data.get("values", [])
            next_url = data.get("next")
            next_params = None  # absolute url in `next`

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------
    def get_pull_request(self, pr_id: int) -> PullRequest:
        resp = self._client.get(self._repo_path(f"/pullrequests/{pr_id}"))
        self._raise(resp, action="get_pull_request")
        data = resp.json()
        return PullRequest(
            id=data["id"],
            title=data.get("title") or "",
            description=data.get("description") or "",
            source_branch=data["source"]["branch"]["name"],
            destination_branch=data["destination"]["branch"]["name"],
            source_commit=data["source"]["commit"]["hash"],
            destination_commit=data["destination"]["commit"]["hash"],
            author=(data.get("author") or {}).get("display_name") or "unknown",
        )

    def get_pull_request_diff(self, pr_id: int) -> str:
        resp = self._client.get(self._repo_path(f"/pullrequests/{pr_id}/diff"))
        self._raise(resp, action="get_pull_request_diff")
        return resp.text

    def list_changed_files(self, pr_id: int) -> list[str]:
        files: list[str] = []
        for entry in self._paginate(self._repo_path(f"/pullrequests/{pr_id}/diffstat")):
            # `new` is the post-change file; for deletions only `old` exists.
            new = entry.get("new") or {}
            path = new.get("path")
            if path:
                files.append(path)
        return files

    def list_comments(self, pr_id: int) -> list[ExistingComment]:
        out: list[ExistingComment] = []
        for c in self._paginate(self._repo_path(f"/pullrequests/{pr_id}/comments")):
            if c.get("deleted"):
                continue
            inline = c.get("inline") or {}
            out.append(ExistingComment(
                id=c["id"],
                file=inline.get("path"),
                line=inline.get("to") or inline.get("from"),
                content=(c.get("content") or {}).get("raw") or "",
            ))
        return out

    def post_summary_comment(self, pr_id: int, body: str) -> dict:
        payload = {"content": {"raw": body}}
        resp = self._client.post(self._repo_path(f"/pullrequests/{pr_id}/comments"), json=payload)
        self._raise(resp, action="post_summary_comment")
        return resp.json()

    def post_inline_comment(self, pr_id: int, comment: InlineComment) -> dict:
        # Bitbucket inline comment: `inline.to` = line in the new file.
        payload = {
            "content": {"raw": comment.body},
            "inline": {"path": comment.file, "to": comment.line},
        }
        resp = self._client.post(self._repo_path(f"/pullrequests/{pr_id}/comments"), json=payload)
        self._raise(resp, action="post_inline_comment")
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BitbucketClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
