"""Subprocess-mocked tests for the Claude CLI adapter."""

import json
import subprocess
from unittest.mock import patch

import pytest

from bugbot.clients.claude_cli import ClaudeCliClient, ClaudeCliError


@pytest.fixture
def fake_which():
    with patch("bugbot.clients.claude_cli.shutil.which", return_value="/usr/local/bin/claude"):
        yield


def _make_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def test_init_raises_if_cli_missing():
    with patch("bugbot.clients.claude_cli.shutil.which", return_value=None):
        with pytest.raises(ClaudeCliError):
            ClaudeCliClient(cli_path="claude-not-installed")


def test_chat_invokes_with_stdin_and_args(fake_which):
    envelope = {
        "type": "result", "subtype": "success",
        "result": "the model's reply",
        "is_error": False,
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))) as run:
        client = ClaudeCliClient(model="opus")
        resp = client.chat(
            system_prompt="you are a reviewer",
            user_prompt="diff here",
            cwd="/tmp/clone",
            allowed_tools=["Read", "Grep"],
        )

    call = run.call_args
    argv = call.args[0]
    # User prompt over stdin — secrets must NOT be in argv.
    assert call.kwargs["input"] == "diff here"
    assert "diff here" not in " ".join(argv)
    # cwd passed through to subprocess.
    assert call.kwargs["cwd"] == "/tmp/clone"
    # System prompt is in argv via --append-system-prompt.
    assert "--append-system-prompt" in argv
    assert "you are a reviewer" in argv
    assert "--model" in argv and "opus" in argv
    assert "--output-format" in argv and "json" in argv
    # Tools enabled, exactly the requested whitelist.
    idx = argv.index("--allowed-tools")
    assert argv[idx + 1] == "Read,Grep"

    assert resp.content == "the model's reply"
    assert resp.prompt_tokens == 100
    assert resp.completion_tokens == 50


def test_chat_refuses_dangerous_tools(fake_which):
    client = ClaudeCliClient()
    with pytest.raises(ClaudeCliError) as ei:
        client.chat(system_prompt="s", user_prompt="u", allowed_tools=["Read", "Bash"])
    assert "Bash" in str(ei.value)


def test_chat_passes_effort_flag(fake_which):
    envelope = {"type": "result", "result": "x", "is_error": False, "usage": {}}
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))) as run:
        ClaudeCliClient().chat(system_prompt="s", user_prompt="u", effort="high")
    argv = run.call_args.args[0]
    idx = argv.index("--effort")
    assert argv[idx + 1] == "high"


def test_chat_omits_effort_when_none(fake_which):
    envelope = {"type": "result", "result": "x", "is_error": False, "usage": {}}
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))) as run:
        ClaudeCliClient().chat(system_prompt="s", user_prompt="u")
    argv = run.call_args.args[0]
    assert "--effort" not in argv


def test_chat_rejects_invalid_effort(fake_which):
    with pytest.raises(ClaudeCliError) as ei:
        ClaudeCliClient().chat(system_prompt="s", user_prompt="u", effort="ludicrous")
    assert "ludicrous" in str(ei.value)


def test_chat_defaults_to_readonly_tools(fake_which):
    envelope = {"type": "result", "result": "x", "is_error": False, "usage": {}}
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))) as run:
        ClaudeCliClient().chat(system_prompt="s", user_prompt="u")
    argv = run.call_args.args[0]
    idx = argv.index("--allowed-tools")
    # Default must be read-only.
    tools = set(argv[idx + 1].split(","))
    assert tools == {"Read", "Grep", "Glob"}


def test_chat_raises_on_nonzero_exit_and_redacts_stderr(fake_which):
    leaky_stderr = "auth failed: sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stderr=leaky_stderr, returncode=1)):
        with pytest.raises(ClaudeCliError) as ei:
            ClaudeCliClient().chat(system_prompt="s", user_prompt="u")
    msg = str(ei.value)
    assert "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in msg
    assert "REDACTED" in msg


def test_chat_raises_on_invalid_json(fake_which):
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout="<<not json>>")):
        with pytest.raises(ClaudeCliError):
            ClaudeCliClient().chat(system_prompt="s", user_prompt="u")


def test_chat_raises_when_envelope_is_error(fake_which):
    envelope = {"type": "result", "is_error": True, "result": "something broke"}
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))):
        with pytest.raises(ClaudeCliError):
            ClaudeCliClient().chat(system_prompt="s", user_prompt="u")


def test_chat_raises_on_timeout(fake_which):
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=1)

    with patch("bugbot.clients.claude_cli.subprocess.run", side_effect=boom):
        with pytest.raises(ClaudeCliError) as ei:
            ClaudeCliClient(timeout=1).chat(system_prompt="s", user_prompt="u")
    assert "timed out" in str(ei.value)


def test_chat_captures_all_four_token_counters(fake_which):
    """The CLI's `usage` envelope reports four counters: input,
    cache_creation_input, cache_read_input, output. The adapter must
    surface all four — `cache_read` is the largest by far for the
    typical bugbot run (system prompt + tool defs replayed from cache)
    and dropping it under-reports cost by ~90%."""
    envelope = {
        "type": "result", "subtype": "success",
        "result": '{"summary": "ok", "findings": []}',
        "is_error": False,
        "usage": {
            "input_tokens": 5,
            "cache_creation_input_tokens": 312,
            "cache_read_input_tokens": 4827,
            "output_tokens": 173,
        },
    }
    with patch("bugbot.clients.claude_cli.subprocess.run",
               return_value=_make_completed(stdout=json.dumps(envelope))):
        resp = ClaudeCliClient().chat(system_prompt="s", user_prompt="u")
    assert resp.prompt_tokens == 5
    assert resp.cache_creation_tokens == 312
    assert resp.cache_read_tokens == 4827
    assert resp.completion_tokens == 173
    # Total spans every counter the API charged for.
    assert resp.total_tokens == 5 + 312 + 4827 + 173
