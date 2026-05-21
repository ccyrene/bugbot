"""Claude Code CLI adapter.

Invokes `claude -p` as a subprocess. The prompt is fed via stdin to keep
secrets out of argv (which is world-readable via /proc on Linux).

We ask for `--output-format json` so we can parse the result envelope and
extract the text reliably across CLI versions.

Expected JSON envelope (Claude Code, --output-format json):

  {
    "type": "result",
    "subtype": "success",
    "result": "<the model's text>",
    "is_error": false,
    "usage": {...}
  }

If the CLI returns a non-zero exit code, or the envelope can't be parsed,
we raise ClaudeCliError. The orchestrator falls back to a "review failed"
summary so the PR still gets a comment — better than silent failures.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from bugbot.libs.logging import get_logger
from bugbot.libs.redact import redact

log = get_logger("claude_cli")


class ClaudeCliError(RuntimeError):
    pass


@dataclass
class ClaudeResponse:
    content: str
    # `prompt_tokens` is the *non-cached* input — i.e. the small delta
    # the model actually processed fresh this call. The bulk of input
    # for a typical bugbot run lives in `cache_read_tokens` (system
    # prompt + tool defs + repeated instructions, replayed from cache).
    prompt_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ClaudeCliClient:
    """Run `claude -p` non-interactively.

    Equivalent shell invocation:
        echo "<prompt>" | claude -p --output-format json --model sonnet \\
            --append-system-prompt "<system prompt>"
    """

    def __init__(
        self,
        *,
        cli_path: str = "claude",
        model: str = "sonnet",
        timeout: float = 300.0,
    ) -> None:
        if not shutil.which(cli_path):
            raise ClaudeCliError(
                f"Claude CLI not found at '{cli_path}'. "
                "Install with `npm i -g @anthropic-ai/claude-code`."
            )
        self._cli = cli_path
        self._model = model
        self._timeout = timeout

    def chat(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        cwd: str | None = None,
        allowed_tools: list[str] | None = None,
        effort: str | None = None,
    ) -> ClaudeResponse:
        """Send a system+user prompt pair and return the model's text.

        Args:
          system_prompt: prepended to the system prompt of the run.
          user_prompt:   the user turn. Passed via stdin (not argv) so
                         it doesn't appear in /proc/<pid>/cmdline.
          cwd:           working directory for the CLI. When set, the
                         model's filesystem tools (Read/Grep/Glob) operate
                         relative to this path. Use this to point at a
                         freshly-cloned PR working tree.
          allowed_tools: whitelist of Claude tools the model may invoke
                         non-interactively. We default to read-only tools
                         (Read, Grep, Glob). NEVER pass Bash/Edit/Write
                         here — bugbot reviews untrusted PR code.
          effort:        Claude reasoning effort level: one of
                         low / medium / high / xhigh / max. Optional —
                         when None we don't pass `--effort` and let the
                         CLI use its default.
        """
        tools = allowed_tools if allowed_tools is not None else ["Read", "Grep", "Glob"]
        # Reject obviously dangerous tools at the boundary, regardless of
        # what the caller passed. This is belt + braces — config can be
        # wrong, but this client is the last line of defence.
        forbidden = {"Bash", "Edit", "Write", "MultiEdit", "WebFetch"}
        bad = sorted(set(tools) & forbidden)
        if bad:
            raise ClaudeCliError(
                f"refusing to allow dangerous tools in PR review: {bad}"
            )

        if effort is not None and effort not in {"low", "medium", "high", "xhigh", "max"}:
            raise ClaudeCliError(f"invalid effort level: {effort!r}")

        argv = [
            self._cli,
            "-p",                              # print/non-interactive mode
            "--output-format", "json",
            "--model", self._model,
            "--append-system-prompt", system_prompt,
            "--allowed-tools", ",".join(tools),
            # `default` keeps interactive permission prompts active — but
            # in -p mode unknown tools are denied, and our allowed list is
            # read-only by construction.
            "--permission-mode", "default",
        ]
        if effort is not None:
            argv += ["--effort", effort]
        log.debug(
            "invoking claude CLI: argv={} stdin_chars={} cwd={} tools={}",
            argv, len(user_prompt), cwd, tools,
        )
        try:
            proc = subprocess.run(
                argv,
                input=user_prompt,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=cwd,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ClaudeCliError(
                f"claude CLI timed out after {self._timeout}s"
            ) from exc
        except FileNotFoundError as exc:
            raise ClaudeCliError(f"claude CLI not invokable: {exc}") from exc

        if proc.returncode != 0:
            # Redact stderr — the CLI sometimes echoes the prompt back on
            # error, and our prompt may contain partial diff context.
            raise ClaudeCliError(
                f"claude CLI exited {proc.returncode}: "
                f"{redact(proc.stderr.strip())[:500]}"
            )

        return self._parse(proc.stdout)

    @staticmethod
    def _parse(stdout: str) -> ClaudeResponse:
        # `--output-format json` emits a single JSON object on stdout.
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ClaudeCliError(
                f"claude CLI did not return JSON. first 200 chars: "
                f"{redact(stdout)[:200]!r}"
            ) from exc

        if isinstance(envelope, dict) and envelope.get("is_error"):
            raise ClaudeCliError(
                f"claude CLI reported error: "
                f"{redact(str(envelope.get('result') or envelope))[:500]}"
            )

        # The text payload lives under .result for type=result. Older CLI
        # versions used .text — accept both.
        content = ""
        if isinstance(envelope, dict):
            content = (envelope.get("result") or envelope.get("text") or "").strip()

        usage = (envelope or {}).get("usage") or {}
        # The CLI surfaces all four counters from the Anthropic API:
        #   - input_tokens               = fresh non-cached input
        #   - cache_creation_input_tokens = input written to prompt cache
        #   - cache_read_input_tokens     = input served from cache (free-ish)
        #   - output_tokens               = model output (incl. tool-use)
        # Totalling all four gives the "real" tokens charged for the call.
        input_t = int(usage.get("input_tokens") or 0)
        cache_create_t = int(usage.get("cache_creation_input_tokens") or 0)
        cache_read_t = int(usage.get("cache_read_input_tokens") or 0)
        output_t = int(usage.get("output_tokens") or 0)
        return ClaudeResponse(
            content=content,
            prompt_tokens=input_t,
            cache_creation_tokens=cache_create_t,
            cache_read_tokens=cache_read_t,
            completion_tokens=output_t,
            total_tokens=input_t + cache_create_t + cache_read_t + output_t,
        )

    def close(self) -> None:
        # Nothing to close — subprocess is one-shot.
        return None

    def __enter__(self) -> "ClaudeCliClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
