"""Review orchestrator.

Flow:
  1. Fetch PR metadata + diff from Bitbucket.
  2. Parse diff; drop ignored files.
  3. Run the local security scanner on added lines.
  4. Build the LLM prompt (diff + pre-scan results, masked).
  5. Invoke the Claude CLI (`claude -p`); parse JSON findings.
  6. Combine LLM findings + scanner findings; cap, dedupe, post.
  7. Post a summary comment and one inline comment per finding.
  8. Return an exit code based on `fail_on_severity`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Literal

from bugbot.clients.bitbucket import BitbucketClient, InlineComment
from bugbot.clients.claude_cli import ClaudeCliClient, ClaudeCliError
from bugbot.config import Settings, Severity
from bugbot.libs.logging import get_logger
from bugbot.libs.redact import redact
from bugbot.services.diff import FileDiff, filter_files, parse_unified_diff
from bugbot.services.repo import GitCloneError, clone_pr_branch
from bugbot.services.security import SecretFinding, highest_severity, scan_diff

log = get_logger("review")

_Category = Literal["security", "correctness", "data-loss", "performance", "secret-leak"]


@dataclass
class Finding:
    file: str
    line: int
    severity: Severity
    category: _Category
    message: str
    source: Literal["scanner", "llm"] = "llm"


@dataclass
class ReviewResult:
    pr_id: int
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    dry_run: bool = False
    posted_inline: int = 0
    posted_summary: bool = False

    @property
    def top_severity(self) -> Severity:
        top = Severity.NONE
        for f in self.findings:
            if f.severity.rank > top.rank:
                top = f.severity
        return top


def _load_prompt(name: str) -> str:
    return resource_files("bugbot.prompts").joinpath(name).read_text(encoding="utf-8")


def _format_security_block(findings: list[SecretFinding]) -> str:
    if not findings:
        return "_No secrets detected by the pre-scan._"
    lines = []
    for f in findings:
        lines.append(
            f"- **{f.severity.value.upper()}** `{f.rule_id}` at `{f.file}:{f.line}` — "
            f"matched: `{f.snippet}` (raw value redacted)"
        )
    return "\n".join(lines)


def _truncate_diff(diff: str, max_chars: int) -> str:
    if len(diff) <= max_chars:
        return diff
    return diff[:max_chars] + f"\n\n… [truncated: diff exceeded {max_chars} chars]"


_LANG_BY_EXT = {
    "py": "python", "js": "javascript", "ts": "typescript", "tsx": "tsx",
    "jsx": "jsx", "go": "go", "rs": "rust", "java": "java", "kt": "kotlin",
    "swift": "swift", "rb": "ruby", "php": "php", "cs": "csharp", "c": "c",
    "h": "c", "cpp": "cpp", "hpp": "cpp", "sh": "bash", "bash": "bash",
    "zsh": "bash", "yml": "yaml", "yaml": "yaml", "json": "json", "toml": "toml",
    "md": "markdown", "sql": "sql", "html": "html", "css": "css",
    "scss": "scss", "dockerfile": "dockerfile",
}


def _lang_hint(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name == "dockerfile":
        return "dockerfile"
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    return _LANG_BY_EXT.get(ext, "")


def _render_changed_files(
    files: list[FileDiff], cwd: Path, max_total_bytes: int,
) -> str:
    """Inline the *post-change* content of each changed file in the user
    prompt, capped at `max_total_bytes`. Read from the cloned working tree
    (cheap, already on disk; avoids an extra Bitbucket API round-trip per
    file).

    Skips deletions, binary files, and anything missing from disk (e.g.
    submodules, symlinks). Caps per-file to keep one giant file from
    eating the whole budget.
    """
    if not files:
        return "_No files changed._"

    per_file_cap = max(max_total_bytes // 4, 8_000)
    blocks: list[str] = []
    total = 0
    skipped_for_budget: list[str] = []

    for f in files:
        if f.is_deleted or f.is_binary:
            continue
        p = cwd / f.path
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(content) > per_file_cap:
            content = content[:per_file_cap] + f"\n\n… [truncated, file is {len(content)} chars]"
        if total + len(content) > max_total_bytes:
            skipped_for_budget.append(f.path)
            continue
        lang = _lang_hint(f.path)
        blocks.append(f"### `{f.path}` (full content)\n\n```{lang}\n{content}\n```")
        total += len(content)

    if skipped_for_budget:
        blocks.append(
            "### Omitted (token budget)\n\n"
            + "\n".join(f"- `{p}`" for p in skipped_for_budget)
        )

    return "\n\n".join(blocks) if blocks else "_No readable file content._"


_JSON_RE = re.compile(r"\{[\s\S]*\}")


def _parse_llm_json(content: str) -> dict:
    # Tolerate models that wrap JSON in markdown fences.
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", stripped, flags=re.MULTILINE).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        m = _JSON_RE.search(stripped)
        if not m:
            raise
        return json.loads(m.group(0))


def _llm_findings_to_model(payload: dict) -> tuple[str, list[Finding]]:
    summary = (payload.get("summary") or "").strip()
    findings: list[Finding] = []
    for raw in payload.get("findings") or []:
        try:
            sev = Severity(str(raw["severity"]).lower())
            findings.append(Finding(
                file=str(raw["file"]),
                line=int(raw["line"]),
                severity=sev,
                category=str(raw.get("category") or "correctness"),  # type: ignore[arg-type]
                message=str(raw["message"]).strip(),
                source="llm",
            ))
        except (KeyError, ValueError, TypeError):
            log.warning("dropping malformed LLM finding: {!r}", raw)
            continue
    return summary, findings


def _scanner_to_findings(scanner_hits: list[SecretFinding]) -> list[Finding]:
    return [
        Finding(
            file=h.file,
            line=h.line,
            severity=h.severity,
            category="secret-leak",
            message=(
                f"Sensitive data leak — rule **{h.rule_name}** (`{h.rule_id}`) matched. "
                f"Value masked as `{h.snippet}`. Rotate the credential and remove it "
                "from version control (history rewrite required)."
            ),
            source="scanner",
        )
        for h in scanner_hits
    ]


def _valid_lines_per_file(files: list[FileDiff]) -> dict[str, set[int]]:
    return {f.path: set(f.added_line_numbers()) for f in files}


def _filter_findings_to_diff(
    findings: list[Finding], valid: dict[str, set[int]]
) -> list[Finding]:
    """Drop findings whose file/line aren't in the diff — Bitbucket would
    reject them anyway, and they erode trust."""
    out: list[Finding] = []
    for f in findings:
        lines = valid.get(f.file)
        if lines is None:
            # Scanner findings always reference added lines, so this is an LLM
            # hallucination; log + drop.
            log.warning("dropping finding on file not in diff: {}:{}", f.file, f.line)
            continue
        if f.line not in lines:
            # If the LLM picked a context line, try to snap to the nearest
            # added line in the same file within 3 lines — otherwise drop.
            nearest = min(lines, key=lambda x: abs(x - f.line), default=None)
            if nearest is not None and abs(nearest - f.line) <= 3:
                log.info("snapped finding {}:{} -> {}", f.file, f.line, nearest)
                f.line = nearest
                out.append(f)
            else:
                log.warning("dropping finding on non-added line: {}:{}", f.file, f.line)
            continue
        out.append(f)
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.category)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    # Sort: scanner first (canonical), then by severity desc, then file/line
    out.sort(key=lambda f: (
        0 if f.source == "scanner" else 1,
        -f.severity.rank,
        f.file,
        f.line,
    ))
    return out


def _already_commented(
    existing: list, marker: str
) -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    for c in existing:
        if marker not in (c.content or ""):
            continue
        if c.file and c.line:
            keys.add((c.file, c.line))
    return keys


_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 critical",
    Severity.HIGH:     "🟠 high",
    Severity.MEDIUM:   "🟡 medium",
    Severity.LOW:      "🔵 low",
    Severity.NONE:     "none",
}


def reviewer_display_name(model: str) -> str:
    """Human-readable name for the LLM doing the review.

    `sonnet`            -> "Claude Sonnet"
    `opus`              -> "Claude Opus"
    `haiku`             -> "Claude Haiku"
    `claude-sonnet-4-6` -> "Claude Sonnet 4.6"
    `claude-opus-4-7`   -> "Claude Opus 4.7"
    fallback            -> "Claude"
    """
    m = model.strip().lower()
    if m in {"sonnet", "opus", "haiku"}:
        return f"Claude {m.capitalize()}"
    if m.startswith("claude-"):
        parts = m[len("claude-"):].split("-")
        if not parts:
            return "Claude"
        family = parts[0].capitalize()
        version = ".".join(parts[1:])
        out = f"Claude {family}"
        if version:
            out += f" {version}"
        return out
    return "Claude"


def _attribution(name: str, marker: str) -> str:
    # Discreet attribution footer + grep-able marker. The marker is rendered
    # as inline code so Bitbucket doesn't show it as HTML-comment plaintext
    # but it's still a substring of the rendered comment for idempotency.
    return f"_— {name} · `{marker}`_"


def _format_inline_body(f: Finding, name: str, marker: str) -> str:
    return (
        f"**{_SEVERITY_BADGE[f.severity]} · {f.category}**\n\n"
        f"{f.message}\n\n"
        f"{_attribution(name, marker)}"
    )


def _format_summary_body(result: ReviewResult, name: str, marker: str) -> str:
    heading = f"## {name} · review"

    if not result.findings:
        body = result.summary or "No issues detected."
        return (
            f"{heading}\n\n"
            f"{body}\n\n"
            f"_No findings._\n\n"
            f"{_attribution(name, marker)}"
        )

    by_sev: dict[Severity, int] = {}
    for f in result.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    counts = " · ".join(
        f"**{by_sev[s]}** {s.value}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if s in by_sev
    )

    lines = [
        heading,
        "",
        result.summary or "_(no summary)_",
        "",
        "---",
        "",
        f"**Findings:** {counts}",
        "",
        "| Severity | File | Line | Category |",
        "| --- | --- | --- | --- |",
    ]
    for f in result.findings:
        lines.append(
            f"| {_SEVERITY_BADGE[f.severity]} | `{f.file}` | {f.line} | {f.category} |"
        )
    lines += [
        "",
        "Inline comments posted on the specific lines above. "
        "Scanner findings (`secret-leak`) are mandatory — rotate before merging.",
        "",
        _attribution(name, marker),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------


class Reviewer:
    """One-shot reviewer for a single PR. Reusable across PRs — pass `pr_id`
    explicitly to `run()` so the same instance can serve a webhook worker."""

    def __init__(
        self,
        settings: Settings,
        *,
        bitbucket: BitbucketClient,
        claude: ClaudeCliClient,
    ) -> None:
        self._s = settings
        self._bb = bitbucket
        self._llm = claude
        self._system_prompt = _load_prompt("system.md")
        self._user_template = _load_prompt("user.md")

    def run(self, pr_id: int) -> ReviewResult:
        s = self._s
        pr = self._bb.get_pull_request(pr_id)
        log.info("PR #{} '{}' by {} ({} -> {})", pr.id, pr.title, pr.author,
                 pr.source_branch, pr.destination_branch)

        diff_text = self._bb.get_pull_request_diff(pr_id)
        all_files = parse_unified_diff(diff_text)
        files = filter_files(all_files, s.ignore_glob_list)
        log.info("diff parsed: {} files, {} ignored",
                 len(files), len(all_files) - len(files))

        scanner_hits = scan_diff(files)
        if scanner_hits:
            log.warning("pre-scan found {} potential secrets (top severity: {})",
                        len(scanner_hits), highest_severity(scanner_hits).value)

        result = ReviewResult(pr_id=pr.id, dry_run=s.dry_run)
        result.findings.extend(_scanner_to_findings(scanner_hits))

        # Clone the PR's source branch into a tmp dir so the LLM can read
        # files around the diff via its read-only tools. Cleaned up on exit.
        try:
            clone_ctx = clone_pr_branch(
                workspace=self._bb.workspace,
                repo_slug=self._bb.repo_slug,
                source_branch=pr.source_branch,
                bitbucket_username=self._bb.username,
                bitbucket_app_password=self._bb.app_password,
                depth=s.git_clone_depth,
                max_mb=s.git_clone_max_mb,
                timeout=s.git_clone_timeout_seconds,
            )
        except GitCloneError as exc:
            log.error("could not clone repo: {}", exc)
            result.summary = (
                "Automated review skipped — bugbot could not clone the PR "
                "branch. Scanner findings (if any) are still posted."
            )
            self._post(result)
            return result

        with clone_ctx as clone:
            log.info("clone ready at {} @ {}", clone.path, clone.head_commit[:8])

            # Build LLM input. Inline the *full post-change content* of
            # every changed file directly in the prompt (Cursor-style) so
            # the model doesn't have to round-trip a Read tool call per
            # file. Diff is still included so the model can see *what*
            # changed. Tools remain available for inspecting un-changed
            # files (callers, configs, schemas) only when needed.
            truncated = _truncate_diff(diff_text, s.max_diff_chars)
            safe_diff = redact(truncated)
            files_block = _render_changed_files(
                files, Path(clone.path), s.max_file_chars,
            )
            safe_files_block = redact(files_block)
            user_prompt = self._user_template.format(
                title=pr.title or "(no title)",
                author=pr.author,
                source_branch=pr.source_branch,
                destination_branch=pr.destination_branch,
                description=pr.description or "_(no description)_",
                security_findings_block=_format_security_block(scanner_hits),
                changed_files_block=safe_files_block,
                diff=safe_diff,
                repo_path=str(clone.path),
                head_commit=clone.head_commit,
            )

            log.info("calling claude CLI (~{} chars, cwd={})",
                     len(user_prompt), clone.path)
            try:
                chat = self._llm.chat(
                    system_prompt=self._system_prompt,
                    user_prompt=user_prompt,
                    cwd=str(clone.path),
                    allowed_tools=s.claude_allowed_tools_list,
                    effort=s.claude_effort,
                )
            except ClaudeCliError as exc:
                log.error("claude CLI failed: {}", exc)
                result.summary = (
                    "Automated review failed: the Claude CLI returned an error. "
                    "Scanner findings (if any) are still posted below."
                )
                self._post(result)
                return result

        # ------- after clone is cleaned up, parse + post -----------------
        result.prompt_tokens = chat.prompt_tokens
        result.completion_tokens = chat.completion_tokens

        try:
            payload = _parse_llm_json(chat.content)
        except json.JSONDecodeError:
            log.error("LLM did not return valid JSON. content (redacted, 500 chars): {}",
                      redact(chat.content)[:500])
            result.summary = "Automated review failed: model did not return parsable JSON."
            payload = {"summary": result.summary, "findings": []}

        summary, llm_findings = _llm_findings_to_model(payload)
        result.summary = summary or "Automated review complete."

        valid = _valid_lines_per_file(files)
        llm_findings = _filter_findings_to_diff(llm_findings, valid)
        result.findings.extend(llm_findings)
        result.findings = _dedupe(result.findings)

        self._post(result)
        log.info(
            "review done — findings={} top={} tokens={}+{}",
            len(result.findings), result.top_severity.value,
            result.prompt_tokens, result.completion_tokens,
        )
        return result

    # ------------------------------------------------------------------
    def _post(self, result: ReviewResult) -> None:
        s = self._s
        marker = s.bot_marker
        name = reviewer_display_name(s.claude_model)

        # Idempotency: pull existing bot comments first.
        if not s.dry_run:
            existing = self._bb.list_comments(result.pr_id)
            already = _already_commented(existing, marker)
        else:
            already = set()

        cap = s.max_inline_comments
        posted = 0
        for f in result.findings:
            if posted >= cap:
                log.info("inline-comment cap reached ({}), stopping", cap)
                break
            if (f.file, f.line) in already:
                log.info("skip already-commented line {}:{}", f.file, f.line)
                continue

            body = _format_inline_body(f, name, marker)
            if s.dry_run:
                print(f"[DRY-RUN inline] {f.file}:{f.line}\n{body}\n")
            else:
                self._bb.post_inline_comment(
                    result.pr_id,
                    InlineComment(file=f.file, line=f.line, body=body),
                )
            posted += 1
        result.posted_inline = posted

        # Summary always — useful audit trail even when no findings.
        summary_body = _format_summary_body(result, name, marker)
        if s.dry_run:
            print(f"[DRY-RUN summary]\n{summary_body}\n")
        else:
            self._bb.post_summary_comment(result.pr_id, summary_body)
            result.posted_summary = True


def result_to_json(result: ReviewResult) -> str:
    payload = {
        "pr_id": result.pr_id,
        "summary": result.summary,
        "top_severity": result.top_severity.value,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "posted_inline": result.posted_inline,
        "posted_summary": result.posted_summary,
        "findings": [
            {
                "file": f.file,
                "line": f.line,
                "severity": f.severity.value,
                "category": f.category,
                "message": f.message,
                "source": f.source,
            }
            for f in result.findings
        ],
    }
    # Defence in depth: never let a raw secret leak via the JSON artefact.
    return redact(json.dumps(payload, indent=2))


__all__ = ["Reviewer", "ReviewResult", "Finding", "result_to_json"]
