"""Snapshot-ish tests for the rendered comment bodies. We're not pinning the
exact characters — only the structural pieces that affect Bitbucket UX:
heading, attribution, marker substring, severity badge, no stray HTML."""

import pytest

from bugbot.config import Severity
from bugbot.services.review import (
    Finding,
    ReviewResult,
    _format_inline_body,
    _format_summary_body,
    reviewer_display_name,
)


@pytest.mark.parametrize("model, expected", [
    ("sonnet", "Claude Sonnet"),
    ("opus", "Claude Opus"),
    ("haiku", "Claude Haiku"),
    ("SONNET", "Claude Sonnet"),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6"),
    ("claude-opus-4-7", "Claude Opus 4.7"),
    ("claude-haiku-4-5-20251001", "Claude Haiku 4.5.20251001"),
    ("", "Claude"),
    ("weird-thing", "Claude"),
])
def test_display_name_variants(model, expected):
    assert reviewer_display_name(model) == expected


def _finding(sev: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        file="api/users.py",
        line=42,
        severity=sev,
        category="security",
        message="SQL injection — use parameterised queries.",
    )


def test_inline_body_has_badge_message_and_attribution():
    body = _format_inline_body(_finding(), "Claude Sonnet", "bugbot:v1")
    # Severity badge with emoji
    assert "🔴 critical" in body
    # Category
    assert "security" in body
    # The actual message
    assert "SQL injection" in body
    # Attribution and grep-able marker (as inline code, not HTML comment)
    assert "Claude Sonnet" in body
    assert "`bugbot:v1`" in body
    # No leaked HTML comment from earlier template
    assert "<!--" not in body
    assert "-->" not in body


def test_inline_body_uses_dynamic_name():
    body = _format_inline_body(_finding(), "Claude Opus 4.7", "bugbot:v1")
    assert "Claude Opus 4.7" in body
    assert "Claude Sonnet" not in body


def test_summary_with_no_findings_renders_cleanly():
    result = ReviewResult(pr_id=1, summary="Looks good.")
    body = _format_summary_body(result, "Claude Sonnet", "bugbot:v1")
    assert body.startswith("## Claude Sonnet · review")
    assert "Looks good." in body
    assert "No findings." in body
    assert "`bugbot:v1`" in body
    # No HTML pollution
    assert "<!--" not in body
    # No empty table when no findings
    assert "| Severity " not in body


def test_summary_with_findings_includes_table_and_counts():
    result = ReviewResult(pr_id=1, summary="Several issues.")
    result.findings = [
        _finding(Severity.CRITICAL),
        Finding(file="api/users.py", line=43, severity=Severity.HIGH,
                category="correctness", message="m"),
        Finding(file="api/users.py", line=44, severity=Severity.MEDIUM,
                category="performance", message="m"),
    ]
    body = _format_summary_body(result, "Claude Sonnet", "bugbot:v1")
    # Heading + summary
    assert "## Claude Sonnet · review" in body
    assert "Several issues." in body
    # Counts line — bold severity counts
    assert "**1** critical" in body
    assert "**1** high" in body
    assert "**1** medium" in body
    # Markdown table (header + separator + rows)
    assert "| Severity |" in body
    assert "| --- |" in body
    # File paths as inline code in the table
    assert "`api/users.py`" in body
    # Footer mentioning scanner findings
    assert "secret-leak" in body
    # Attribution at bottom
    assert "`bugbot:v1`" in body


def test_marker_substring_findable_for_idempotency():
    """The orchestrator uses `marker in comment.content` to know whether
    it has already commented on a line. The rendered marker must contain
    the bare substring, not be wrapped in something that breaks it."""
    body = _format_inline_body(_finding(), "Claude Sonnet", "bugbot:v1")
    assert "bugbot:v1" in body
