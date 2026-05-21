"""GitHub webhook event extractor.

We accept the `pull_request` event with these actions as triggers:

  * `opened`            — PR created
  * `reopened`          — PR re-opened
  * `synchronize`       — new commits pushed → re-review
  * `ready_for_review`  — promoted from draft → review

Anything else (labeled, edited, closed, merged, review-requested, …) is
acknowledged 204 so GitHub doesn't retry, but doesn't trigger a review.

Payload reference:
  https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request
"""

from __future__ import annotations

from bugbot.server.webhook import WebhookEvent, WebhookParseError


GITHUB_TRIGGER_ACTIONS = frozenset({
    "opened",
    "reopened",
    "synchronize",
    "ready_for_review",
})

# Actions we recognise but deliberately ignore. Anything outside this set is
# logged as "unknown" so we notice if GitHub adds new actions we should
# react to.
GITHUB_KNOWN_ACTIONS = GITHUB_TRIGGER_ACTIONS | frozenset({
    "closed",
    "edited",
    "assigned",
    "unassigned",
    "labeled",
    "unlabeled",
    "review_requested",
    "review_request_removed",
    "converted_to_draft",
    "auto_merge_enabled",
    "auto_merge_disabled",
    "locked",
    "unlocked",
    "milestoned",
    "demilestoned",
    "enqueued",
    "dequeued",
})


def parse_github_webhook(*, event_header: str | None, payload: dict) -> WebhookEvent:
    """Parse a `pull_request` event payload.

    Only `pull_request` events trigger; everything else (push, issues,
    issue_comment, …) raises WebhookParseError so the app handler can
    204 it.
    """
    if not event_header:
        raise WebhookParseError("missing X-GitHub-Event header")
    if event_header != "pull_request":
        raise WebhookParseError(f"unsupported event family: {event_header}")

    action = str(payload.get("action") or "").strip()
    if not action:
        raise WebhookParseError("pull_request payload missing 'action'")

    repo = payload.get("repository") or {}
    pr = payload.get("pull_request") or {}
    sender = payload.get("sender") or {}

    full_name = repo.get("full_name") or ""
    if "/" not in full_name:
        raise WebhookParseError(
            f"repository.full_name missing or invalid: {full_name!r}"
        )
    owner, repo_slug = full_name.split("/", 1)

    pr_number = pr.get("number")
    if not isinstance(pr_number, int):
        raise WebhookParseError(
            f"pull_request.number missing or not int: {pr_number!r}"
        )

    # Surface a Bitbucket-style synthetic event_key so the logger and the
    # rest of the pipeline get a uniform string.
    synthetic_key = f"pull_request:{action}"
    is_trigger = action in GITHUB_TRIGGER_ACTIONS
    # Draft PRs: `opened`+draft=True → don't review until ready_for_review.
    if action == "opened" and pr.get("draft") is True:
        is_trigger = False

    actor = sender.get("login") or "unknown"

    return WebhookEvent(
        event_key=synthetic_key,
        workspace=owner,
        repo_slug=repo_slug,
        pr_id=pr_number,
        actor=actor,
        is_trigger=is_trigger,
        provider="github",
    )
