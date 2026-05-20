"""Defence-in-depth: redact obvious secrets from any string that may leave
the process (LLM prompt, log line, posted comment). Pattern set mirrors the
security scanner but the goal here is **masking**, not detection."""

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****REDACTED****"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "ghp_****REDACTED****"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "github_pat_****REDACTED****"),
    (re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "glpat-****REDACTED****"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "xox*-****REDACTED****"),
    (re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"), "sk-or-v1-****REDACTED****"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "sk-****REDACTED****"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
     "-----BEGIN PRIVATE KEY----- ****REDACTED**** -----END PRIVATE KEY-----"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
     r"\1=****REDACTED****"),
    (re.compile(r"(postgres|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@",
                re.IGNORECASE), r"\1://****:****@"),
    # Any URL with embedded basic-auth — covers git clone URLs (bitbucket.org,
    # github.com, gitlab.com, …) and arbitrary internal services.
    (re.compile(r"(https?)://[^:\s/@]+:[^@\s/]+@", re.IGNORECASE),
     r"\1://****:****@"),
]


def redact(text: str) -> str:
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out
