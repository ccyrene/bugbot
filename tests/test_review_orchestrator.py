"""Tests for the orchestrator's pure logic — formatting, snapping, dedupe.
Network-heavy paths are covered by the bitbucket / claude_cli client tests."""

from bugbot.config import Severity
from bugbot.services.diff import parse_unified_diff
from bugbot.services.review import (
    Finding,
    _dedupe,
    _filter_findings_to_diff,
    _format_security_block,
    _llm_findings_to_model,
    _load_focus,
    _load_prompt,
    _parse_llm_json,
    _valid_lines_per_file,
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
