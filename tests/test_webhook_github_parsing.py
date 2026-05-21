"""GitHub `pull_request` webhook parser tests."""

import pytest

from bugbot.server.webhook import WebhookParseError
from bugbot.server.webhook_github import parse_github_webhook


def _payload(action: str = "opened", number: int = 7, draft: bool = False) -> dict:
    return {
        "action": action,
        "repository": {"full_name": "acme/widget"},
        "pull_request": {"number": number, "title": "do thing", "draft": draft},
        "sender": {"login": "alice"},
    }


@pytest.mark.parametrize("action", ["opened", "reopened", "synchronize", "ready_for_review"])
def test_trigger_actions_set_should_review(action):
    ev = parse_github_webhook(event_header="pull_request", payload=_payload(action=action))
    assert ev.provider == "github"
    assert ev.workspace == "acme"
    assert ev.repo_slug == "widget"
    assert ev.pr_id == 7
    assert ev.should_review is True
    # We synthesise a Bitbucket-style event_key so logs and dedupe keys are
    # uniform across providers.
    assert ev.event_key == f"pull_request:{action}"


@pytest.mark.parametrize("action", ["closed", "edited", "labeled", "review_requested"])
def test_known_non_trigger_actions_are_parsed_but_skipped(action):
    ev = parse_github_webhook(event_header="pull_request", payload=_payload(action=action))
    assert ev.should_review is False


def test_draft_opened_does_not_trigger():
    ev = parse_github_webhook(
        event_header="pull_request",
        payload=_payload(action="opened", draft=True),
    )
    # Draft PRs aren't review-ready — wait for ready_for_review.
    assert ev.should_review is False


def test_ready_for_review_does_trigger_even_if_draft_flag_lingers():
    ev = parse_github_webhook(
        event_header="pull_request",
        payload=_payload(action="ready_for_review", draft=True),
    )
    assert ev.should_review is True


def test_missing_event_header_raises():
    with pytest.raises(WebhookParseError):
        parse_github_webhook(event_header=None, payload=_payload())


def test_non_pull_request_event_raises():
    with pytest.raises(WebhookParseError):
        parse_github_webhook(event_header="issues", payload=_payload())


def test_missing_action_raises():
    payload = _payload()
    payload.pop("action")
    with pytest.raises(WebhookParseError):
        parse_github_webhook(event_header="pull_request", payload=payload)


def test_missing_repo_full_name_raises():
    payload = _payload()
    payload["repository"] = {}
    with pytest.raises(WebhookParseError):
        parse_github_webhook(event_header="pull_request", payload=payload)


def test_missing_pr_number_raises():
    payload = _payload()
    payload["pull_request"] = {}
    with pytest.raises(WebhookParseError):
        parse_github_webhook(event_header="pull_request", payload=payload)
