"""Tests for the orchestrator's pure logic — formatting, snapping, dedupe.
Network-heavy paths are covered by the bitbucket / claude_cli client tests."""

from unittest.mock import MagicMock

from pydantic import SecretStr

from bugbot.config import Settings, Severity
from bugbot.services.diff import parse_unified_diff
from bugbot.services.review import (
    Finding,
    ReviewResult,
    Reviewer,
    _dedupe,
    _filter_findings_to_diff,
    _format_security_block,
    _llm_findings_to_model,
    _load_focus,
    _load_prompt,
    _parse_llm_json,
    _valid_lines_per_file,
    result_to_json,
)
from bugbot.services.security import SecretFinding


DIFF = """diff --git a/app.py b/app.py
index 0..1 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+x = 1
+y = 2
+z = 3
"""


def _f(file: str, line: int, sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(file=file, line=line, severity=sev, category="correctness", message="m")


def test_valid_lines_per_file_from_diff():
    files = parse_unified_diff(DIFF)
    valid = _valid_lines_per_file(files)
    assert valid == {"app.py": {2, 3, 4}}


def test_filter_drops_findings_on_unknown_file():
    files = parse_unified_diff(DIFF)
    valid = _valid_lines_per_file(files)
    out = _filter_findings_to_diff([_f("missing.py", 2)], valid)
    assert out == []


def test_filter_snaps_finding_to_nearest_added_line():
    files = parse_unified_diff(DIFF)
    valid = _valid_lines_per_file(files)
    # Line 5 doesn't exist in the diff; nearest added is 4 (delta=1) — snap.
    out = _filter_findings_to_diff([_f("app.py", 5)], valid)
    assert len(out) == 1
    assert out[0].line == 4


def test_filter_drops_finding_too_far_from_added_line():
    files = parse_unified_diff(DIFF)
    valid = _valid_lines_per_file(files)
    # Line 100 is way off — drop.
    out = _filter_findings_to_diff([_f("app.py", 100)], valid)
    assert out == []


def test_dedupe_collapses_same_file_line_category():
    a = _f("app.py", 2)
    b = _f("app.py", 2)  # duplicate
    c = _f("app.py", 3)
    out = _dedupe([a, b, c])
    assert len(out) == 2


def test_dedupe_sorts_scanner_first_then_by_severity():
    llm_med = Finding("a.py", 1, Severity.MEDIUM, "correctness", "m", source="llm")
    scanner_low = Finding("a.py", 2, Severity.LOW, "secret-leak", "s", source="scanner")
    llm_high = Finding("a.py", 3, Severity.HIGH, "correctness", "h", source="llm")
    out = _dedupe([llm_med, scanner_low, llm_high])
    # scanner comes first regardless of severity ranking.
    assert out[0] is scanner_low
    # then LLM findings by severity desc.
    assert out[1] is llm_high
    assert out[2] is llm_med


def test_parse_llm_json_strips_markdown_fence():
    raw = '```json\n{"summary": "ok", "findings": []}\n```'
    out = _parse_llm_json(raw)
    assert out == {"summary": "ok", "findings": []}


def test_parse_llm_json_extracts_object_from_prose():
    raw = 'Here is the review: {"summary":"x","findings":[]} thanks!'
    out = _parse_llm_json(raw)
    assert out["summary"] == "x"


def test_security_block_formats_with_masked_snippet():
    hits = [
        SecretFinding(
            file="a.py", line=3,
            rule_id="openai-key", rule_name="OpenAI API key",
            severity=Severity.CRITICAL,
            snippet="sk-…ab (51 chars)",
            raw_match="sk-proj-FULL-RAW-VALUE-NEVER-LEAKED",
        ),
    ]
    block = _format_security_block(hits)
    assert "CRITICAL" in block
    assert "openai-key" in block
    assert "a.py:3" in block
    assert "sk-proj-FULL-RAW-VALUE-NEVER-LEAKED" not in block


def test_security_block_when_empty():
    assert "No secrets" in _format_security_block([])


# ----------------------------------------------------------------------
# Per-domain focus prompts
# ----------------------------------------------------------------------


def test_focus_general_has_security_priority():
    """`general` is the fallback domain — it must look like the original
    pre-domain prompt so existing deployments aren't silently weakened."""
    block = _load_focus("general")
    assert "Security data leak" in block
    assert "Correctness bugs" in block


def test_focus_data_eng_mentions_pipeline_specific_landmines():
    block = _load_focus("data-eng")
    # We care about the focus being domain-flavoured — not the exact
    # wording. Spot-check a few terms that are unmistakably data-eng.
    text = block.lower()
    assert "schema" in text or "migration" in text or "partition" in text
    assert "airflow" in text or "dag" in text or "pipeline" in text


def test_focus_asr_mentions_speech_and_training_landmines():
    block = _load_focus("asr")
    text = block.lower()
    # Five priority areas the user requested are all represented.
    assert "leakage" in text
    assert "reproducibility" in text or "seed" in text
    assert "loss" in text or "gradient" in text
    assert "sample rate" in text or "spec" in text or "audio" in text
    # The ASR-specific cues are why we shipped a separate file at all —
    # losing them would mean this collapses back into the general prompt.
    assert "speaker" in text or "asr" in text


def test_unknown_domain_falls_back_to_general():
    # Typo in BUGBOT_REPO_DOMAINS shouldn't produce an empty focus block —
    # the reviewer would have no priorities and freelance them.
    fallback = _load_focus("does-not-exist")
    general = _load_focus("general")
    assert fallback == general


# ----------------------------------------------------------------------
# Suggestion field parsing
# ----------------------------------------------------------------------


def test_llm_finding_with_suggestion_parses_through():
    payload = {
        "summary": "ok",
        "findings": [{
            "file": "app.py", "line": 3, "severity": "high",
            "category": "correctness", "message": "use ==",
            "suggestion": "if foo == 1:",
        }],
    }
    _, findings = _llm_findings_to_model(payload)
    assert len(findings) == 1
    assert findings[0].suggestion == "if foo == 1:"
    assert findings[0].suggestion_start_line is None


def test_llm_finding_with_empty_suggestion_treated_as_none():
    # The model sometimes emits `""` instead of omitting the field. Treat
    # that as "no suggestion" so we don't render an empty code fence.
    payload = {
        "summary": "ok",
        "findings": [{
            "file": "app.py", "line": 3, "severity": "high",
            "category": "correctness", "message": "m",
            "suggestion": "   ",
        }],
    }
    _, findings = _llm_findings_to_model(payload)
    assert findings[0].suggestion is None


def test_llm_finding_with_multiline_suggestion_keeps_start_line():
    payload = {
        "summary": "ok",
        "findings": [{
            "file": "app.py", "line": 5, "severity": "medium",
            "category": "correctness", "message": "m",
            "suggestion": "for i in range(n):\n    x += i",
            "suggestion_start_line": 4,
        }],
    }
    _, findings = _llm_findings_to_model(payload)
    assert findings[0].suggestion_start_line == 4
    assert "\n" in findings[0].suggestion


def test_llm_finding_drops_start_line_greater_than_line():
    # `suggestion_start_line` must be <= `line` for GitHub's range API.
    # Reverse order means model is confused — keep finding, drop range.
    payload = {
        "summary": "ok",
        "findings": [{
            "file": "app.py", "line": 3, "severity": "low",
            "category": "correctness", "message": "m",
            "suggestion": "foo",
            "suggestion_start_line": 9,
        }],
    }
    _, findings = _llm_findings_to_model(payload)
    assert findings[0].suggestion == "foo"
    assert findings[0].suggestion_start_line is None


def _reviewer_with_mock_provider():
    """Build a Reviewer wired to a MagicMock provider so we can inspect
    posted comments without making any network calls. Bypasses the
    constructor's real ClaudeCliClient check."""
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        bitbucket_app_password=SecretStr("p"),
        webhook_secret=SecretStr("s"),
        bot_marker="bugbot:v1",
        dry_run=False,
    )
    provider = MagicMock()
    provider.clone_host = "github.com"
    provider.list_comments.return_value = []  # No existing bot comments.
    # Skip __init__ to avoid the ClaudeCliClient binary check.
    rv: Reviewer = Reviewer.__new__(Reviewer)
    rv._s = settings  # type: ignore[attr-defined]
    rv._provider = provider  # type: ignore[attr-defined]
    rv._head_commit = "deadbeef"  # type: ignore[attr-defined]
    return rv, provider


def test_post_splits_has_suggestion_findings_into_own_comments():
    """A file with a mix of has-suggestion and no-suggestion findings
    should produce: one standalone comment per has-suggestion finding
    (so GitHub's ```suggestion fence applies at the right line) plus
    one merged comment for the rest."""
    rv, provider = _reviewer_with_mock_provider()
    findings = [
        # Scanner findings on the same file, no suggestions — should merge.
        Finding("api/users.py", 19, Severity.CRITICAL, "secret-leak",
                "AWS key", source="scanner"),
        Finding("api/users.py", 20, Severity.CRITICAL, "secret-leak",
                "AWS secret", source="scanner"),
        # LLM finding with a suggestion — must get its own comment so
        # the ```suggestion fence is anchored at line 44, not at 19.
        Finding("api/users.py", 44, Severity.HIGH, "correctness",
                "use env vars", source="llm",
                suggestion="boto3.client('s3', region_name=AWS_REGION)"),
    ]
    result = ReviewResult(pr_id=1)
    result.findings = findings
    rv._post(result)  # type: ignore[attr-defined]

    posted = provider.post_inline_comment.call_args_list
    assert len(posted) == 2  # 1 standalone (suggestion) + 1 grouped (scanners)

    # The standalone has-suggestion comment anchors at line 44 and has
    # the ```suggestion fence the user can apply in one click.
    suggestion_call = next(
        c for c in posted if c.args[1].line == 44
    )
    assert suggestion_call.args[1].file == "api/users.py"
    assert "```suggestion" in suggestion_call.args[1].body

    # The grouped no-suggestion comment anchors at the worst-severity
    # finding's line (19, a critical scanner hit) and merges both
    # scanner findings.
    grouped_call = next(
        c for c in posted if c.args[1].line == 19
    )
    body = grouped_call.args[1].body
    assert "2 findings in `api/users.py`" in body
    assert "Line 19" in body and "Line 20" in body
    assert "```suggestion" not in body  # no suggestion in this batch


def test_post_groups_when_all_findings_lack_suggestions():
    """All scanner findings → 1 merged comment per file, zero standalone."""
    rv, provider = _reviewer_with_mock_provider()
    findings = [
        Finding("a.py", 1, Severity.CRITICAL, "secret-leak", "m1", source="scanner"),
        Finding("a.py", 2, Severity.HIGH, "secret-leak", "m2", source="scanner"),
    ]
    result = ReviewResult(pr_id=1)
    result.findings = findings
    rv._post(result)  # type: ignore[attr-defined]

    posted = provider.post_inline_comment.call_args_list
    assert len(posted) == 1
    assert posted[0].args[1].line == 1  # anchored at the worst (critical)


def test_post_one_comment_per_finding_when_all_have_suggestions():
    """All LLM findings carry suggestions → each gets its own
    standalone comment so every ```suggestion fence is clickable."""
    rv, provider = _reviewer_with_mock_provider()
    findings = [
        Finding("a.py", 5, Severity.HIGH, "correctness", "m1",
                suggestion="fix1"),
        Finding("a.py", 10, Severity.MEDIUM, "correctness", "m2",
                suggestion="fix2"),
    ]
    result = ReviewResult(pr_id=1)
    result.findings = findings
    rv._post(result)  # type: ignore[attr-defined]

    posted = provider.post_inline_comment.call_args_list
    assert len(posted) == 2
    # Each anchored at its own line so the GitHub fence applies right.
    lines = sorted(c.args[1].line for c in posted)
    assert lines == [5, 10]


def test_post_per_file_idempotency_skips_files_with_existing_bot_comment():
    """File-level dedupe: if a previous review already left a bot
    comment on a file, the re-review skips that file entirely (both
    the standalone suggestion comments and the grouped one)."""
    rv, provider = _reviewer_with_mock_provider()
    # Pretend the previous review left a bugbot:v1-marked inline on a.py.
    existing = MagicMock()
    existing.content = "old finding _— Claude · `bugbot:v1`_"
    existing.file = "a.py"
    existing.line = 1
    provider.list_comments.return_value = [existing]

    result = ReviewResult(pr_id=1)
    result.findings = [
        Finding("a.py", 5, Severity.HIGH, "correctness", "m1",
                suggestion="fix"),
        Finding("a.py", 10, Severity.MEDIUM, "correctness", "m2"),
        Finding("b.py", 1, Severity.LOW, "correctness", "m3"),
    ]
    rv._post(result)  # type: ignore[attr-defined]

    posted = provider.post_inline_comment.call_args_list
    # a.py is skipped entirely (had bot comment); only b.py gets posted.
    files_posted = {c.args[1].file for c in posted}
    assert files_posted == {"b.py"}


def test_result_to_json_includes_suggestion_fields():
    """Operators inspecting the artefact should be able to tell which
    findings carry a suggestion — without this, debugging "why isn't
    there a clickable fix?" requires re-running the review."""
    result = ReviewResult(pr_id=1, summary="ok")
    result.findings = [
        Finding("a.py", 1, Severity.HIGH, "correctness", "m1",
                suggestion="x = 1", suggestion_start_line=1),
        Finding("a.py", 5, Severity.LOW, "correctness", "m2"),  # no fix
    ]
    payload = result_to_json(result)
    import json as _json
    parsed = _json.loads(payload)
    assert parsed["findings"][0]["suggestion"] == "x = 1"
    assert parsed["findings"][0]["suggestion_start_line"] == 1
    assert parsed["findings"][1]["suggestion"] is None
    assert parsed["findings"][1]["suggestion_start_line"] is None


def test_filter_drops_suggestion_when_start_line_not_in_diff():
    files = parse_unified_diff(DIFF)
    valid = _valid_lines_per_file(files)
    f = Finding(
        file="app.py", line=4, severity=Severity.LOW,
        category="correctness", message="m",
        suggestion="z = 99", suggestion_start_line=1,  # line 1 is context, not +
    )
    out = _filter_findings_to_diff([f], valid)
    assert len(out) == 1
    # Finding survives, just without the suggestion attached.
    assert out[0].suggestion is None
    assert out[0].suggestion_start_line is None


def test_system_template_substitutes_focus_block_into_full_prompt():
    """End-to-end: system.md has a `{focus_block}` placeholder, and the
    reviewer uses str.replace() (not str.format) so the literal `{...}`
    JSON output schema inside system.md doesn't conflict."""
    template = _load_prompt("system.md")
    rendered = template.replace("{focus_block}", _load_focus("asr"))
    # Universal rules survive.
    assert "Only comment on lines that are added in this diff" in rendered
    # Domain focus landed in place of the placeholder.
    assert "{focus_block}" not in rendered
    assert "speaker" in rendered.lower() or "leakage" in rendered.lower()
    # The JSON output-schema example must still be present and intact
    # (broken-format-string regression would mangle it).
    assert '"summary"' in rendered
    assert '"findings"' in rendered
