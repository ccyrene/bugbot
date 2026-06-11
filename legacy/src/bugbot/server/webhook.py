"""Bitbucket Cloud webhook event extractor.

We accept these PR events as triggers:

  * `pullrequest:created`
  * `pullrequest:updated`     (new commits pushed → re-review)
  * `pullrequest:fulfilled`   (merged — we still post nothing, ignore)
  * `pullrequest:rejected`    (declined — ignore)

We trigger reviews only on `created` and `updated`. Everything else is
acknowledged with 204 so Bitbucket doesn't retry.

Payload reference:
  https://support.atlassian.com/bitbucket-cloud/docs/event-payloads/#pull-request-events
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


TRIGGER_EVENTS = frozenset({
    "pullrequest:created",
    "pullrequest:updated",
})

KNOWN_EVENTS = TRIGGER_EVENTS | frozenset({
    "pullrequest:fulfilled",
    "pullrequest:rejected",
    "pullrequest:approved",
    "pullrequest:unapproved",
    "pullrequest:comment_created",
    "pullrequest:comment_updated",
    "pullrequest:comment_deleted",
})


Provider = Literal["bitbucket", "github"]


@dataclass(frozen=True)
class WebhookEvent:
    event_key: str
    workspace: str
    repo_slug: str
    pr_id: int
    actor: str
    is_trigger: bool
    provider: Provider = "bitbucket"

    @property
    def should_review(self) -> bool:
        return self.is_trigger


class WebhookParseError(ValueError):
    pass


def parse_webhook(*, event_key: str | None, payload: dict) -> WebhookEvent:
    if not event_key:
        raise WebhookParseError("missing X-Event-Key header")
    if not event_key.startswith("pullrequest:"):
        raise WebhookParseError(f"unsupported event family: {event_key}")

    repo = payload.get("repository") or {}
    pr = payload.get("pullrequest") or {}
    actor = (payload.get("actor") or {}).get("display_name") or "unknown"

    full_name = repo.get("full_name") or ""
    if "/" not in full_name:
        raise WebhookParseError(
            f"repository.full_name missing or invalid: {full_name!r}"
        )
    workspace, repo_slug = full_name.split("/", 1)

    pr_id = pr.get("id")
    if not isinstance(pr_id, int):
        raise WebhookParseError(f"pullrequest.id missing or not int: {pr_id!r}")

    return WebhookEvent(
        event_key=event_key,
        workspace=workspace,
        repo_slug=repo_slug,
        pr_id=pr_id,
        actor=actor,
        is_trigger=event_key in TRIGGER_EVENTS,
        provider="bitbucket",
    )
