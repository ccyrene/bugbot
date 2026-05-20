"""Secret / sensitive-data scanner.

Runs over the **added lines** of a PR diff. Goals, in order:

1. **Mandatory blocker** — if a HIGH/CRITICAL secret looks committed,
   the orchestrator must fail the build no matter what the LLM says.
2. **Don't leak it to the LLM** — when we add findings into the LLM
   context, the secret value itself is masked.
3. **Low false positive rate** — pattern + entropy + per-rule allowlist.

Heuristics are deliberately conservative: we'd rather miss a weak password
than spam every PR with false positives. Bias the rules toward markers that
are unambiguous (provider-issued key prefixes, BEGIN PRIVATE KEY blocks,
explicit `password=` next to non-placeholder values).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

from bugbot.config import Severity
from bugbot.services.diff import FileDiff


@dataclass(frozen=True)
class SecretFinding:
    file: str
    line: int
    rule_id: str
    rule_name: str
    severity: Severity
    snippet: str  # already-masked excerpt safe to render
    raw_match: str  # original (sensitive!) — kept ONLY for local use, never serialised


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    min_entropy: float | None = None  # if set, require Shannon entropy >= this
    # substrings that, if present, indicate a clearly placeholder value
    placeholders: tuple[str, ...] = ()


# ---- placeholder denylist shared by generic rules ------------------------
_PLACEHOLDER_TOKENS = (
    "your-", "your_", "xxxx", "changeme", "change-me", "example",
    "placeholder", "redacted", "dummy", "fake-", "sample", "<", ">",
    "todo", "tbd", "n/a", "none", "null",
)

_RULES: tuple[_Rule, ...] = (
    # --- Cloud providers ---------------------------------------------------
    _Rule("aws-access-key", "AWS Access Key ID", Severity.CRITICAL,
          re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Rule("aws-secret-key", "AWS Secret Access Key", Severity.CRITICAL,
          re.compile(
              r"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
          min_entropy=4.0),
    _Rule("gcp-service-account", "GCP service account private key", Severity.CRITICAL,
          re.compile(r'"type"\s*:\s*"service_account"')),

    # --- Private keys ------------------------------------------------------
    _Rule("private-key-pem", "PEM private key", Severity.CRITICAL,
          re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),

    # --- VCS / CI tokens ---------------------------------------------------
    _Rule("github-token", "GitHub personal access token", Severity.HIGH,
          re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    _Rule("github-fine-grained", "GitHub fine-grained PAT", Severity.HIGH,
          re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    _Rule("gitlab-token", "GitLab PAT", Severity.HIGH,
          re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    _Rule("bitbucket-app-password", "Bitbucket App Password (suspected)", Severity.HIGH,
          re.compile(r"(?i)bitbucket[_-]?(?:app[_-]?password|token)\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]")),

    # --- Chat / messaging --------------------------------------------------
    _Rule("slack-token", "Slack token", Severity.HIGH,
          re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b")),
    _Rule("slack-webhook", "Slack incoming webhook", Severity.HIGH,
          re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    _Rule("discord-webhook", "Discord webhook", Severity.HIGH,
          re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+")),
    _Rule("telegram-bot-token", "Telegram bot token", Severity.HIGH,
          re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b")),

    # --- LLM providers (very important — devs paste these) -----------------
    _Rule("openai-key", "OpenAI API key", Severity.CRITICAL,
          # Avoid double-flagging anthropic (sk-ant-) and openrouter (sk-or-v1-)
          # which have their own dedicated rules.
          re.compile(r"\bsk-(?!ant-|or-v1-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    _Rule("anthropic-key", "Anthropic API key", Severity.CRITICAL,
          re.compile(r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{30,}\b")),
    _Rule("openrouter-key", "OpenRouter API key", Severity.CRITICAL,
          re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}\b")),
    _Rule("google-api-key", "Google API key", Severity.HIGH,
          re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),

    # --- Generic high-signal ----------------------------------------------
    _Rule("jwt", "JSON Web Token (signed)", Severity.MEDIUM,
          re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    _Rule("db-url-with-creds", "Database URL with embedded credentials", Severity.CRITICAL,
          re.compile(
              r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|clickhouse)://"
              r"[^:\s/]+:[^@\s]+@[^\s'\"]+",
              re.IGNORECASE)),
    _Rule("password-assignment", "Hard-coded password assignment", Severity.HIGH,
          re.compile(
              r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"),
          placeholders=_PLACEHOLDER_TOKENS),
    _Rule("secret-assignment", "Hard-coded secret/api key assignment", Severity.HIGH,
          re.compile(
              r"(?i)(secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret)"
              r"\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"),
          placeholders=_PLACEHOLDER_TOKENS,
          min_entropy=3.0),
    _Rule("basic-auth-url", "URL with basic auth credentials", Severity.HIGH,
          re.compile(r"\bhttps?://[^/\s:@]+:[^/\s@]{4,}@[^\s'\"]+")),

    # --- PII (light touch — flag, don't block by default) -----------------
    _Rule("private-ipv4", "Private/internal IPv4 address", Severity.LOW,
          re.compile(
              r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b")),
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in _PLACEHOLDER_TOKENS)


def _mask(value: str) -> str:
    """Return a masked excerpt safe to render in comments / prompts."""
    if len(value) <= 8:
        return "****"
    return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"


def _candidate_value(match: re.Match[str]) -> str:
    """Pick the most-secret-looking captured group."""
    if match.lastindex:
        # last captured group is usually the value
        return match.group(match.lastindex)
    return match.group(0)


def scan_line(file: str, lineno: int, content: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for rule in _RULES:
        for m in rule.pattern.finditer(content):
            value = _candidate_value(m)
            if rule.placeholders and _looks_like_placeholder(value):
                continue
            if rule.min_entropy is not None:
                if _shannon_entropy(value) < rule.min_entropy:
                    continue
            findings.append(SecretFinding(
                file=file,
                line=lineno,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                snippet=_mask(value),
                raw_match=value,
            ))
    return findings


def scan_diff(files: Iterable[FileDiff]) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for f in files:
        if f.is_binary or f.is_deleted:
            continue
        for lineno, content in f.added_lines():
            findings.extend(scan_line(f.path, lineno, content))
    return findings


def highest_severity(findings: Iterable[SecretFinding]) -> Severity:
    top = Severity.NONE
    for f in findings:
        if f.severity.rank > top.rank:
            top = f.severity
    return top
