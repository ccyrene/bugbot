"""Config edge cases — env-var aliases + defaults that matter."""

import os

import pytest

from bugbot.config import Settings


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    # pydantic-settings reads from the process env by default. Wipe any
    # BUGBOT_* / BITBUCKET_* the caller might already have set so tests
    # start from a known blank state.
    for key in list(os.environ):
        if key.startswith(("BUGBOT_", "BITBUCKET_")):
            monkeypatch.delenv(key, raising=False)


def _set_required(monkeypatch, *, token_key="BUGBOT_BITBUCKET_APP_PASSWORD"):
    monkeypatch.setenv(token_key, "ATBBtoken123")
    monkeypatch.setenv("BUGBOT_WEBHOOK_SECRET", "wh-secret")


def test_default_username_is_x_token_auth(monkeypatch):
    _set_required(monkeypatch)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.bitbucket_username == "x-token-auth"


def test_bitbucket_token_env_alias_is_accepted(monkeypatch):
    # User keeps BITBUCKET_TOKEN — bugbot should still pick it up.
    monkeypatch.setenv("BITBUCKET_TOKEN", "ATBBaliasvalue")
    monkeypatch.setenv("BUGBOT_WEBHOOK_SECRET", "wh-secret")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.bitbucket_app_password.get_secret_value() == "ATBBaliasvalue"


def test_canonical_bugbot_var_takes_precedence_over_alias(monkeypatch):
    monkeypatch.setenv("BUGBOT_BITBUCKET_APP_PASSWORD", "canonical")
    monkeypatch.setenv("BITBUCKET_TOKEN", "alias")
    monkeypatch.setenv("BUGBOT_WEBHOOK_SECRET", "wh-secret")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.bitbucket_app_password.get_secret_value() == "canonical"


def test_claude_effort_default_is_high(monkeypatch):
    _set_required(monkeypatch)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.claude_effort == "high"


def test_claude_effort_rejects_unknown_level(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("BUGBOT_CLAUDE_EFFORT", "ludicrous")
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]
