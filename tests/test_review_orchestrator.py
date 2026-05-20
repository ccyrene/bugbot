"""Tests for the orchestrator's pure logic — formatting, snapping, dedupe.
Network-heavy paths are covered by the bitbucket / claude_cli client tests."""

from bugbot.config import Severity
from bugbot.services.diff import parse_unified_diff
from bugbot.services.review import (
    Finding,
    _dedupe,
    _filter_findings_to_diff,
    _format_security_block,
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
