import pytest

from bugbot.server.webhook import (
    TRIGGER_EVENTS,
    WebhookParseError,
    parse_webhook,
)


def _payload(pr_id: int = 42, full_name: str = "my-ws/my-repo") -> dict:
    return {
        "repository": {"full_name": full_name},
        "pullrequest": {"id": pr_id, "title": "do thing"},
        "actor": {"display_name": "Alice"},
    }


def test_parses_created_event_as_trigger():
    ev = parse_webhook(event_key="pullrequest:created", payload=_payload())
    assert ev.workspace == "my-ws"
    assert ev.repo_slug == "my-repo"
    assert ev.pr_id == 42
    assert ev.is_trigger is True
    assert ev.should_review is True


def test_parses_updated_event_as_trigger():
    ev = parse_webhook(event_key="pullrequest:updated", payload=_payload())
    assert ev.is_trigger is True


@pytest.mark.parametrize("event_key", [
    "pullrequest:fulfilled", "pullrequest:rejected",
    "pullrequest:approved", "pullrequest:comment_created",
])
def test_non_trigger_pr_events_are_parsed_but_skipped(event_key):
    ev = parse_webhook(event_key=event_key, payload=_payload())
    assert ev.is_trigger is False
    assert ev.should_review is False


def test_missing_event_header_raises():
    with pytest.raises(WebhookParseError):
        parse_webhook(event_key=None, payload=_payload())


def test_non_pullrequest_event_raises():
    with pytest.raises(WebhookParseError):
        parse_webhook(event_key="repo:push", payload=_payload())


def test_missing_repo_full_name_raises():
    payload = _payload()
    payload["repository"] = {}
    with pytest.raises(WebhookParseError):
        parse_webhook(event_key="pullrequest:created", payload=payload)


def test_missing_pr_id_raises():
    payload = _payload()
    payload["pullrequest"] = {}
    with pytest.raises(WebhookParseError):
        parse_webhook(event_key="pullrequest:created", payload=payload)


def test_trigger_set_is_exactly_create_and_update():
    assert TRIGGER_EVENTS == frozenset({
        "pullrequest:created", "pullrequest:updated",
    })
