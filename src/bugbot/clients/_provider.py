"""Shared data models + Protocol for PR providers (Bitbucket, GitHub, …).

The orchestrator (`bugbot.services.review.Reviewer`) talks to whichever
client implements `PullRequestProvider` — it doesn't care which forge the
PR came from. Keep this surface small: every method below is *required*
by the reviewer, and adding a new one obligates every existing provider
to implement it.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class PullRequest(BaseModel):
    id: int
    title: str
    description: str = ""
    source_branch: str
    destination_branch: str
    # `source_commit` is the HEAD of the PR branch — GitHub requires it on
    # every inline review comment (`commit_id`). Bitbucket ignores it on
    # the wire but we still surface it for parity.
    source_commit: str
    destination_commit: str
    author: str


class InlineComment(BaseModel):
    file: str
    line: int
    body: str
    # GitHub-only: head commit the comment is anchored to. The orchestrator
    # populates it from `PullRequest.source_commit`. Bitbucket's client
    # ignores it.
    commit_id: str | None = None
    # Multi-line suggestion support (GitHub). When set and `start_line !=
    # line`, the GitHub client sends `start_line` + `start_side` so the
    # suggestion block replaces the [start_line, line] range. Bitbucket's
    # client ignores it (Bitbucket has no native suggestion concept).
    start_line: int | None = None


class ExistingComment(BaseModel):
    id: int
    file: str | None
    line: int | None
    content: str


class PullRequestProvider(Protocol):
    """Read+write surface the reviewer needs from any forge."""

    @property
    def workspace(self) -> str: ...  # GitHub: owner; Bitbucket: workspace

    @property
    def repo_slug(self) -> str: ...

    @property
    def username(self) -> str: ...

    @property
    def app_password(self) -> str: ...

    @property
    def clone_host(self) -> str: ...  # e.g. "bitbucket.org" / "github.com"

    def get_pull_request(self, pr_id: int) -> PullRequest: ...

    def get_pull_request_diff(self, pr_id: int) -> str: ...

    def list_comments(self, pr_id: int) -> list[ExistingComment]: ...

    def post_summary_comment(self, pr_id: int, body: str) -> dict: ...

    def post_inline_comment(self, pr_id: int, comment: InlineComment) -> dict: ...

    def close(self) -> None: ...


__all__ = [
    "PullRequest",
    "InlineComment",
    "ExistingComment",
    "PullRequestProvider",
]
