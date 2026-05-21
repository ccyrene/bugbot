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


def test_claude_effort_defaults_to_none(monkeypatch):
    # Default is None because claude-code 2.1.x silently fails when
    # `--effort` is passed alongside `-p`. The orchestrator omits the flag
    # entirely when this is None. Re-enable when upstream is fixed.
    _set_required(monkeypatch)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.claude_effort is None


def test_claude_effort_accepts_explicit_high(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("BUGBOT_CLAUDE_EFFORT", "high")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.claude_effort == "high"


def test_claude_effort_rejects_unknown_level(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("BUGBOT_CLAUDE_EFFORT", "ludicrous")
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]


# ----------------------------------------------------------------------
# Provider validation: at least one provider configured, each with its
# own webhook secret.
# ----------------------------------------------------------------------


def test_no_provider_configured_raises(monkeypatch):
    # Only the webhook secret is set — neither provider's credential is
    # present. The server has nothing to do; refuse to start.
    monkeypatch.setenv("BUGBOT_WEBHOOK_SECRET", "wh")
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_github_only_works_without_bitbucket(monkeypatch):
    # GitHub-only deployment: Bitbucket creds intentionally omitted.
    monkeypatch.setenv("BUGBOT_GITHUB_TOKEN", "ghp_xxx")
    monkeypatch.setenv("BUGBOT_GITHUB_WEBHOOK_SECRET", "ghwh")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.github_enabled is True
    assert s.bitbucket_enabled is False


def test_github_token_env_alias_is_accepted(monkeypatch):
    # Users who already export GITHUB_TOKEN in CI shouldn't have to rename.
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_alias")
    monkeypatch.setenv("BUGBOT_GITHUB_WEBHOOK_SECRET", "ghwh")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.github_token is not None
    assert s.github_token.get_secret_value() == "ghp_alias"


def test_github_enabled_requires_github_webhook_secret(monkeypatch):
    # Refuse to start if a webhook would arrive with no shared secret to
    # verify against — silent acceptance of unsigned hooks is unsafe.
    monkeypatch.setenv("BUGBOT_GITHUB_TOKEN", "ghp_xxx")
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_bitbucket_enabled_requires_bitbucket_webhook_secret(monkeypatch):
    monkeypatch.setenv("BUGBOT_BITBUCKET_APP_PASSWORD", "ATBB")
    # No BUGBOT_WEBHOOK_SECRET — config validator should reject.
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_both_providers_simultaneously(monkeypatch):
    monkeypatch.setenv("BUGBOT_BITBUCKET_APP_PASSWORD", "ATBB")
    monkeypatch.setenv("BUGBOT_WEBHOOK_SECRET", "bbwh")
    monkeypatch.setenv("BUGBOT_GITHUB_TOKEN", "ghp_xxx")
    monkeypatch.setenv("BUGBOT_GITHUB_WEBHOOK_SECRET", "ghwh")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.bitbucket_enabled and s.github_enabled


# ----------------------------------------------------------------------
# Domain default. The actual domain selection happens via webhook URL
# path (e.g. /webhook/github/asr); this just controls what the bare path
# falls back to.
# ----------------------------------------------------------------------


def test_default_domain_is_general(monkeypatch):
    _set_required(monkeypatch)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.default_domain == "general"


def test_default_domain_can_be_overridden(monkeypatch):
    # Useful when most repos are ML — set this once and `/webhook/github`
    # bare path implicitly picks the ML focus.
    _set_required(monkeypatch)
    monkeypatch.setenv("BUGBOT_DEFAULT_DOMAIN", "asr")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.default_domain == "asr"
