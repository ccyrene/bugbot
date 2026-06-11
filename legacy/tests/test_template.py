"""Snapshot-ish tests for the rendered comment bodies. We're not pinning the
exact characters — only the structural pieces that affect Bitbucket UX:
heading, attribution, marker substring, severity badge, no stray HTML."""

import pytest

from bugbot.config import Severity
from bugbot.services.review import (
    Finding,
    ReviewResult,
    _format_grouped_inline_body,
    _format_inline_body,
    _format_summary_body,
    _group_findings_by_file,
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


# ----------------------------------------------------------------------
# Provider-specific suggestion blocks
# ----------------------------------------------------------------------


def _finding_with_suggestion() -> Finding:
    return Finding(
        file="api/users.py",
        line=42,
        severity=Severity.HIGH,
        category="correctness",
        message="Missing await on async fetch.",
        suggestion="result = await fetch()",
    )


def test_github_inline_body_uses_suggestion_fence():
    """On GitHub the suggestion must be in a ```suggestion fence so the
    PR author gets the one-click "Commit suggestion" button. Anything
    else (plain ``` or ```python) does NOT trigger that UI affordance."""
    body = _format_inline_body(
        _finding_with_suggestion(), "Claude Sonnet", "bugbot:v1",
        provider_kind="github",
    )
    assert "```suggestion" in body
    assert "result = await fetch()" in body
    # The replacement closes the fence cleanly — no straggling backticks.
    assert body.count("```") == 2  # opening + closing


def test_bitbucket_inline_body_uses_plain_fence_with_label():
    """Bitbucket Cloud has no native suggestion concept. Render the same
    content in a plain code fence with a label so the reader knows it's
    a *proposed* replacement, not just an inline code sample."""
    body = _format_inline_body(
        _finding_with_suggestion(), "Claude Sonnet", "bugbot:v1",
        provider_kind="bitbucket",
    )
    assert "```suggestion" not in body
    assert "_Suggested fix:_" in body
    assert "result = await fetch()" in body


def test_inline_body_omits_suggestion_block_when_no_suggestion():
    """A finding without a `suggestion` field should render exactly like
    pre-suggestion bugbot — no empty fence, no stray label."""
    body = _format_inline_body(
        _finding(), "Claude Sonnet", "bugbot:v1", provider_kind="github",
    )
    assert "```suggestion" not in body
    assert "_Suggested fix:_" not in body
    assert "```" not in body  # no fence of any kind


# ----------------------------------------------------------------------
# Per-file grouping
# ----------------------------------------------------------------------


def test_group_findings_sorts_severity_desc_then_line_asc():
    """Within a file the worst severity comes first (so it becomes the
    anchor); files themselves sort by their worst severity too (so a
    cap on inline comments hits the most important files first)."""
    findings = [
        Finding("a.py", 5, Severity.LOW, "correctness", "low on a"),
        Finding("b.py", 2, Severity.CRITICAL, "security", "crit on b"),
        Finding("a.py", 1, Severity.HIGH, "correctness", "high on a"),
        Finding("a.py", 7, Severity.HIGH, "correctness", "high2 on a"),
    ]
    groups = _group_findings_by_file(findings)
    # b.py first because it holds a critical; a.py second.
    assert [g[0].file for g in groups] == ["b.py", "a.py"]
    # Within a.py: high (line 1) before high (line 7) before low (line 5).
    a_lines = [f.line for f in groups[1]]
    assert a_lines == [1, 7, 5]


def test_grouped_body_combines_all_findings_into_one_comment():
    findings = [
        Finding("api/users.py", 42, Severity.CRITICAL, "security",
                "Hardcoded API key."),
        Finding("api/users.py", 87, Severity.MEDIUM, "correctness",
                "Missing input validation."),
        Finding("api/users.py", 105, Severity.LOW, "performance",
                "Inefficient list comprehension."),
    ]
    body = _format_grouped_inline_body(
        findings, "Claude Sonnet", "bugbot:v1", provider_kind="github",
    )
    # Header announces the count + worst severity + file.
    assert "3 findings in `api/users.py`" in body
    assert "🔴 critical" in body  # worst severity in header
    # Each finding gets its own section with its line + severity badge.
    assert "Line 42" in body
    assert "Line 87" in body
    assert "Line 105" in body
    # All three message bodies survive into the merged comment.
    assert "Hardcoded API key" in body
    assert "Missing input validation" in body
    assert "Inefficient list comprehension" in body
    # Marker still there for idempotency.
    assert "bugbot:v1" in body


def test_grouped_body_only_anchor_gets_github_suggestion_fence():
    """Only the worst-severity (anchor) finding's suggestion may use the
    ```suggestion fence — GitHub anchors the whole comment at one line,
    so applying a non-anchor suggestion there would patch the wrong
    code."""
    findings = [
        Finding("a.py", 10, Severity.CRITICAL, "security",
                "anchor msg", suggestion="anchor_fix()"),
        Finding("a.py", 20, Severity.MEDIUM, "correctness",
                "other msg", suggestion="other_fix()"),
    ]
    body = _format_grouped_inline_body(
        findings, "Claude Sonnet", "bugbot:v1", provider_kind="github",
    )
    # Anchor (line 10) → real ```suggestion fence
    assert "```suggestion\nanchor_fix()\n```" in body
    # Non-anchor (line 20) → plain ``` fence labelled as a suggestion
    assert "_Suggested fix:_" in body
    assert "```\nother_fix()\n```" in body


def test_grouped_body_falls_back_to_single_when_one_finding():
    """A "group" of one finding should render exactly like the
    pre-grouping single-finding format (no section headers, no count
    line) — those decorations only earn their keep when there are
    multiple findings."""
    f = Finding("a.py", 10, Severity.HIGH, "correctness", "single msg")
    body = _format_grouped_inline_body(
        [f], "Claude Sonnet", "bugbot:v1", provider_kind="github",
    )
    # No grouping decorations for a single finding.
    assert "findings in" not in body
    assert "### Line" not in body
    assert "single msg" in body


def test_grouped_body_bitbucket_provider_uses_plain_fence_throughout():
    """Bitbucket has no native suggestion concept — neither the anchor
    nor the others get the ```suggestion fence; they all get plain
    ``` fences with a label so the reader sees them as proposals, not
    as bugbot's own code."""
    findings = [
        Finding("a.py", 10, Severity.CRITICAL, "security",
                "msg1", suggestion="fix1"),
        Finding("a.py", 20, Severity.MEDIUM, "correctness",
                "msg2", suggestion="fix2"),
    ]
    body = _format_grouped_inline_body(
        findings, "Claude Sonnet", "bugbot:v1", provider_kind="bitbucket",
    )
    assert "```suggestion" not in body
    # Both suggestions show up in plain code fences.
    assert "fix1" in body
    assert "fix2" in body
