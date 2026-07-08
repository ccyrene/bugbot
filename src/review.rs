//! Review orchestrator. Ported from `services/review.py`.
//!
//! Flow: fetch PR + diff → parse/filter → secret scan → clone + scrub →
//! build prompt → run LLM (Review mode, codex `--output-schema`) → parse +
//! validate findings → group + post inline/summary comments.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use regex::{Captures, Regex};
use serde_json::{json, Value};

use crate::clients::llm::{LlmBackend, LlmMode, LlmRequest, TokenUsage};
use crate::clients::provider::{InlineComment, Provider};
use crate::config::{LlmBackendKind, Settings, Severity};
use crate::libs::redact::redact;
use crate::prompts;
use crate::services::diff::{filter_files, parse_unified_diff, FileDiff};
use crate::services::repo::{self, clone_pr_branch, CloneOptions};
use crate::services::security::{highest_severity, scan_diff, SecretFinding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSource {
    Scanner,
    Llm,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: u32,
    pub severity: Severity,
    pub category: String,
    /// Short (3-8 word) headline, e.g. "Category enum out of sync" — rendered
    /// as the comment's heading instead of a bare severity/category tag.
    pub title: String,
    pub message: String,
    pub source: FindingSource,
    pub suggestion: Option<String>,
    pub suggestion_start_line: Option<u32>,
}

#[derive(Debug, Default)]
pub struct ReviewResult {
    pub pr_id: u64,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub usage: TokenUsage,
    pub dry_run: bool,
    pub posted_inline: usize,
    pub posted_summary: bool,
    /// Set when the review pipeline itself didn't complete (clone failure,
    /// LLM error, unparsable LLM output) — as opposed to completing cleanly
    /// with zero findings. Used to keep a Check Run from reporting
    /// `neutral`/`success` when the review never actually ran.
    pub aborted: bool,
}

impl ReviewResult {
    pub fn top_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::None)
    }
}

// ---- findings JSON schema (codex --output-schema) -------------------------

/// JSON Schema for the model's response. All properties are `required` and the
/// optional ones are nullable — the shape OpenAI strict structured output
/// wants (which codex `--output-schema` uses under the hood).
pub fn findings_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["summary", "findings"],
        "properties": {
            "summary": { "type": "string" },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["file", "line", "severity", "category", "title", "message", "suggestion", "suggestion_start_line"],
                    "properties": {
                        "file": { "type": "string" },
                        "line": { "type": "integer" },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
                        "category": { "type": "string", "enum": ["security", "correctness", "data-loss", "performance", "secret-leak", "maintainability"] },
                        "title": { "type": "string" },
                        "message": { "type": "string" },
                        "suggestion": { "type": ["string", "null"] },
                        "suggestion_start_line": { "type": ["integer", "null"] }
                    }
                }
            }
        }
    })
}

// ---- prompt building ------------------------------------------------------

fn format_security_block(findings: &[SecretFinding]) -> String {
    if findings.is_empty() {
        return "_No secrets detected by the pre-scan._".to_string();
    }
    findings
        .iter()
        .map(|f| {
            format!(
                "- **{}** `{}` at `{}:{}` — matched: `{}` (raw value redacted)",
                f.severity.as_str().to_uppercase(),
                f.rule_id,
                f.file,
                f.line,
                f.snippet
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn truncate_diff(diff: &str, max_chars: usize) -> String {
    if diff.len() <= max_chars {
        return diff.to_string();
    }
    let cut = diff
        .char_indices()
        .nth(max_chars)
        .map(|(i, _)| i)
        .unwrap_or(diff.len());
    format!(
        "{}\n\n… [truncated: diff exceeded {} chars]",
        &diff[..cut],
        max_chars
    )
}

static LANG_BY_EXT: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    [
        ("py", "python"),
        ("js", "javascript"),
        ("ts", "typescript"),
        ("tsx", "tsx"),
        ("jsx", "jsx"),
        ("go", "go"),
        ("rs", "rust"),
        ("java", "java"),
        ("kt", "kotlin"),
        ("swift", "swift"),
        ("rb", "ruby"),
        ("php", "php"),
        ("cs", "csharp"),
        ("c", "c"),
        ("h", "c"),
        ("cpp", "cpp"),
        ("hpp", "cpp"),
        ("sh", "bash"),
        ("bash", "bash"),
        ("zsh", "bash"),
        ("yml", "yaml"),
        ("yaml", "yaml"),
        ("json", "json"),
        ("toml", "toml"),
        ("md", "markdown"),
        ("sql", "sql"),
        ("html", "html"),
        ("css", "css"),
        ("scss", "scss"),
        ("dockerfile", "dockerfile"),
    ]
    .into_iter()
    .collect()
});

fn lang_hint(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if name == "dockerfile" {
        return "dockerfile";
    }
    let ext = name.rsplit('.').next().unwrap_or("");
    LANG_BY_EXT.get(ext).copied().unwrap_or("")
}

/// Inline the post-change content of each changed file, capped at
/// `max_total_bytes`. Reads from the cloned tree (already on disk).
fn render_changed_files(files: &[FileDiff], cwd: &Path, max_total_bytes: usize) -> String {
    if files.is_empty() {
        return "_No files changed._".to_string();
    }
    let per_file_cap = (max_total_bytes / 4).max(8_000);
    let mut blocks: Vec<String> = Vec::new();
    let mut total = 0usize;
    let mut skipped: Vec<String> = Vec::new();

    for f in files {
        if f.is_deleted || f.is_binary {
            continue;
        }
        let p = cwd.join(f.path());
        if !p.is_file() {
            continue;
        }
        let Ok(mut content) = std::fs::read_to_string(&p) else {
            continue;
        };
        if content.len() > per_file_cap {
            let cut = content
                .char_indices()
                .nth(per_file_cap)
                .map(|(i, _)| i)
                .unwrap_or(content.len());
            content = format!(
                "{}\n\n… [truncated, file is {} chars]",
                &content[..cut],
                content.len()
            );
        }
        if total + content.len() > max_total_bytes {
            skipped.push(f.path().to_string());
            continue;
        }
        let lang = lang_hint(f.path());
        blocks.push(format!(
            "### `{}` (full content)\n\n```{}\n{}\n```",
            f.path(),
            lang,
            content
        ));
        total += content.len();
    }

    if !skipped.is_empty() {
        let list = skipped
            .iter()
            .map(|p| format!("- `{p}`"))
            .collect::<Vec<_>>()
            .join("\n");
        blocks.push(format!("### Omitted (token budget)\n\n{list}"));
    }
    if blocks.is_empty() {
        "_No readable file content._".to_string()
    } else {
        blocks.join("\n\n")
    }
}

static TEMPLATE_VAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([a-z_]+)\}").expect("template var re"));

/// Single-pass template fill: replaces `{key}` tokens from `vars`, leaving
/// inserted content un-rescanned (so a diff containing `{diff}` is safe).
fn render_template(tpl: &str, vars: &HashMap<&str, String>) -> String {
    TEMPLATE_VAR_RE
        .replace_all(tpl, |c: &Captures| {
            vars.get(&c[1]).cloned().unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

// ---- LLM JSON parsing -----------------------------------------------------

static JSON_OBJ_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\{.*\}").expect("json obj re"));

/// Parse the model's JSON, tolerating markdown fences (claude path; codex with
/// `--output-schema` returns clean JSON already).
fn parse_llm_json(content: &str) -> Result<Value, serde_json::Error> {
    let mut stripped = content.trim().to_string();
    if stripped.starts_with("```") {
        // strip leading ```json / ``` and trailing ```
        stripped = stripped
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string();
    }
    match serde_json::from_str::<Value>(&stripped) {
        Ok(v) => Ok(v),
        Err(e) => {
            if let Some(m) = JSON_OBJ_RE.find(&stripped) {
                serde_json::from_str::<Value>(m.as_str())
            } else {
                Err(e)
            }
        }
    }
}

fn llm_findings_to_model(payload: &Value) -> (String, Vec<Finding>) {
    let summary = payload
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut findings = Vec::new();
    let empty = vec![];
    let raw_findings = payload
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for raw in raw_findings {
        let (Some(file), Some(line_v), Some(sev_s), Some(message)) = (
            raw.get("file").and_then(Value::as_str),
            raw.get("line"),
            raw.get("severity").and_then(Value::as_str),
            raw.get("message").and_then(Value::as_str),
        ) else {
            tracing::warn!("dropping malformed LLM finding: {raw}");
            continue;
        };
        let Some(severity) = Severity::parse(sev_s) else {
            tracing::warn!("dropping finding with bad severity {sev_s:?}");
            continue;
        };
        let line = match line_v.as_i64() {
            Some(n) if n > 0 => n as u32,
            _ => {
                tracing::warn!("dropping finding with bad line {line_v:?}");
                continue;
            }
        };
        let suggestion = raw
            .get("suggestion")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty());
        let suggestion_start_line = match raw.get("suggestion_start_line").and_then(Value::as_i64) {
            Some(sl) if sl > 0 && (sl as u32) <= line => Some(sl as u32),
            Some(sl) => {
                tracing::warn!("dropping suggestion_start_line {sl} > line {line}");
                None
            }
            None => None,
        };
        let category = raw
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("correctness")
            .to_string();
        let title = raw
            .get("title")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{category} finding"));
        findings.push(Finding {
            file: file.to_string(),
            line,
            severity,
            category,
            title,
            message: message.trim().to_string(),
            source: FindingSource::Llm,
            suggestion,
            suggestion_start_line,
        });
    }
    (summary, findings)
}

fn scanner_to_findings(hits: &[SecretFinding]) -> Vec<Finding> {
    hits.iter()
        .map(|h| Finding {
            file: h.file.clone(),
            line: h.line,
            severity: h.severity,
            category: "secret-leak".to_string(),
            title: format!("Secret leak: {}", h.rule_name),
            message: format!(
                "Sensitive data leak — rule **{}** (`{}`) matched. Value masked as `{}`. \
                 Rotate the credential and remove it from version control (history rewrite required).",
                h.rule_name, h.rule_id, h.snippet
            ),
            source: FindingSource::Scanner,
            suggestion: None,
            suggestion_start_line: None,
        })
        .collect()
}

fn valid_lines_per_file(files: &[FileDiff]) -> HashMap<String, HashSet<u32>> {
    files
        .iter()
        .map(|f| {
            (
                f.path().to_string(),
                f.added_line_numbers().into_iter().collect(),
            )
        })
        .collect()
}

/// Drop findings whose file/line aren't added lines (the forge would reject
/// them); snap context-line picks to the nearest added line within 3.
fn filter_findings_to_diff(
    findings: Vec<Finding>,
    valid: &HashMap<String, HashSet<u32>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for mut f in findings {
        let Some(lines) = valid.get(&f.file) else {
            tracing::warn!(
                "dropping finding on file not in diff: {}:{}",
                f.file,
                f.line
            );
            continue;
        };
        if !lines.contains(&f.line) {
            let nearest = lines
                .iter()
                .min_by_key(|&&x| (x as i64 - f.line as i64).abs());
            match nearest {
                Some(&n) if (n as i64 - f.line as i64).abs() <= 3 => {
                    tracing::info!("snapped finding {}:{} -> {}", f.file, f.line, n);
                    f.line = n;
                }
                _ => {
                    tracing::warn!("dropping finding on non-added line: {}:{}", f.file, f.line);
                    continue;
                }
            }
        }
        if let Some(sl) = f.suggestion_start_line {
            if !lines.contains(&sl) {
                tracing::warn!(
                    "dropping suggestion_start_line {sl} (not in diff) for {}",
                    f.file
                );
                f.suggestion = None;
                f.suggestion_start_line = None;
            }
        }
        out.push(f);
    }
    out
}

fn dedupe(mut findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<(String, u32, String)> = HashSet::new();
    findings.retain(|f| seen.insert((f.file.clone(), f.line, f.category.clone())));
    // scanner first, then severity desc, then file, then line.
    findings.sort_by(|a, b| {
        let sa = if a.source == FindingSource::Scanner {
            0
        } else {
            1
        };
        let sb = if b.source == FindingSource::Scanner {
            0
        } else {
            1
        };
        sa.cmp(&sb)
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });
    findings
}

fn group_findings_by_file(findings: &[Finding]) -> Vec<Vec<Finding>> {
    let mut by_file: HashMap<String, Vec<Finding>> = HashMap::new();
    for f in findings {
        by_file.entry(f.file.clone()).or_default().push(f.clone());
    }
    let mut groups: Vec<Vec<Finding>> = by_file.into_values().collect();
    for g in &mut groups {
        g.sort_by(|a, b| {
            b.severity
                .rank()
                .cmp(&a.severity.rank())
                .then(a.line.cmp(&b.line))
        });
    }
    groups.sort_by(|a, b| {
        b[0].severity
            .rank()
            .cmp(&a[0].severity.rank())
            .then(a[0].file.cmp(&b[0].file))
    });
    groups
}

// ---- comment formatting ---------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    GitHub,
    Bitbucket,
}

fn severity_badge(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 critical",
        Severity::High => "🟠 high",
        Severity::Medium => "🟡 medium",
        Severity::Low => "🔵 low",
        Severity::None => "none",
    }
}

/// Footer for inline/grouped comments: the model that produced the review, plus
/// a HIDDEN idempotency marker (HTML comment — invisible on GitHub, but still
/// matched by `already_commented_files`).
fn attribution(name: &str, marker: &str) -> String {
    format!("_— {name}_\n\n<!-- {marker} -->")
}

/// Footer for the summary comment: model + total token usage + hidden marker.
fn attribution_usage(name: &str, usage: &TokenUsage, marker: &str) -> String {
    let toks = usage.compact();
    let head = if toks.is_empty() {
        format!("_— {name}_")
    } else {
        format!("_— {name} · {toks}_")
    };
    format!("{head}\n\n<!-- {marker} -->")
}

fn format_inline_body(f: &Finding, name: &str, marker: &str, kind: ProviderKind) -> String {
    let mut parts = vec![
        format!("### {}", f.title),
        String::new(),
        format!("**{}** · {}", severity_badge(f.severity), f.category),
        String::new(),
        f.message.clone(),
    ];
    if let Some(sug) = &f.suggestion {
        let body = sug.trim_end_matches('\n');
        if kind == ProviderKind::GitHub {
            parts.extend(["".into(), "```suggestion".into(), body.into(), "```".into()]);
        } else {
            parts.extend([
                "".into(),
                "_Suggested fix:_".into(),
                "```".into(),
                body.into(),
                "```".into(),
            ]);
        }
    }
    parts.push(String::new());
    parts.push(attribution(name, marker));
    parts.join("\n")
}

fn format_grouped_inline_body(
    group: &[Finding],
    name: &str,
    marker: &str,
    kind: ProviderKind,
) -> String {
    if group.len() == 1 {
        return format_inline_body(&group[0], name, marker, kind);
    }
    let file = &group[0].file;
    let worst = group[0].severity;
    let mut parts = vec![format!(
        "**{} · {} findings in `{}`**",
        severity_badge(worst),
        group.len(),
        file
    )];
    for (idx, f) in group.iter().enumerate() {
        let is_anchor = idx == 0;
        parts.extend([
            "".into(),
            "---".into(),
            "".into(),
            format!("### {}", f.title),
            "".into(),
            format!(
                "**{}** · {} · line {}",
                severity_badge(f.severity),
                f.category,
                f.line
            ),
            "".into(),
            f.message.clone(),
        ]);
        if let Some(sug) = &f.suggestion {
            let body = sug.trim_end_matches('\n');
            if is_anchor && kind == ProviderKind::GitHub {
                parts.extend(["".into(), "```suggestion".into(), body.into(), "```".into()]);
            } else {
                parts.extend([
                    "".into(),
                    "_Suggested fix:_".into(),
                    "```".into(),
                    body.into(),
                    "```".into(),
                ]);
            }
        }
    }
    parts.push(String::new());
    parts.push(attribution(name, marker));
    parts.join("\n")
}

fn format_summary_body(result: &ReviewResult, name: &str, marker: &str) -> String {
    let heading = format!("## {name} · review");
    if result.findings.is_empty() {
        let body = if result.summary.is_empty() {
            "No issues detected."
        } else {
            &result.summary
        };
        return format!(
            "{heading}\n\n{body}\n\n_No findings._\n\n{}",
            attribution_usage(name, &result.usage, marker)
        );
    }
    let mut by_sev: HashMap<Severity, usize> = HashMap::new();
    for f in &result.findings {
        *by_sev.entry(f.severity).or_insert(0) += 1;
    }
    let counts = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter_map(|s| by_sev.get(&s).map(|n| format!("**{n}** {}", s.as_str())))
    .collect::<Vec<_>>()
    .join(" · ");
    let mut lines = vec![
        heading,
        String::new(),
        if result.summary.is_empty() {
            "_(no summary)_".into()
        } else {
            result.summary.clone()
        },
        String::new(),
        "---".into(),
        String::new(),
        format!("**Findings:** {counts}"),
        String::new(),
        "| Severity | Finding | File | Line | Category |".into(),
        "| --- | --- | --- | --- | --- |".into(),
    ];
    for f in &result.findings {
        lines.push(format!(
            "| {} | {} | `{}` | {} | {} |",
            severity_badge(f.severity),
            f.title,
            f.file,
            f.line,
            f.category
        ));
    }
    lines.extend([
        String::new(),
        "Inline comments posted on the specific lines above. Scanner findings (`secret-leak`) are mandatory — rotate before merging.".into(),
        String::new(),
        attribution_usage(name, &result.usage, marker),
    ]);
    lines.join("\n")
}

fn already_commented_files(
    existing: &[crate::clients::provider::ExistingComment],
    marker: &str,
) -> HashSet<String> {
    existing
        .iter()
        .filter(|c| c.content.contains(marker))
        .filter_map(|c| c.file.clone())
        .collect()
}

// ---- the reviewer ---------------------------------------------------------

pub struct Reviewer<'a> {
    s: &'a Settings,
    provider: &'a Provider,
    llm: &'a LlmBackend,
}

impl<'a> Reviewer<'a> {
    pub fn new(s: &'a Settings, provider: &'a Provider, llm: &'a LlmBackend) -> Self {
        Reviewer { s, provider, llm }
    }

    fn review_timeout(&self) -> Duration {
        let secs = match self.s.llm_backend {
            LlmBackendKind::Codex => self.s.codex_timeout_seconds,
            LlmBackendKind::Claude => self.s.claude_timeout_seconds,
        };
        Duration::from_secs_f64(secs)
    }

    pub async fn run(&self, pr_id: u64, domain: &str) -> anyhow::Result<ReviewResult> {
        let s = self.s;
        let pr = self.provider.get_pull_request(pr_id).await?;
        let head_commit = pr.source_commit.clone();
        tracing::info!(
            "PR #{} '{}' by {} ({} -> {})",
            pr.id,
            pr.title,
            pr.author,
            pr.source_branch,
            pr.destination_branch
        );

        let diff_text = self.provider.get_pull_request_diff(pr_id).await?;
        let all_files = parse_unified_diff(&diff_text);
        let n_all = all_files.len();
        let files = filter_files(all_files, &s.ignore_glob_list());
        tracing::info!(
            "diff parsed: {} files, {} ignored",
            files.len(),
            n_all - files.len()
        );

        let scanner_hits = scan_diff(&files);
        if !scanner_hits.is_empty() {
            tracing::warn!(
                "pre-scan found {} potential secrets (top: {})",
                scanner_hits.len(),
                highest_severity(&scanner_hits).as_str()
            );
        }

        let mut result = ReviewResult {
            pr_id: pr.id,
            dry_run: s.dry_run,
            ..Default::default()
        };
        result.findings.extend(scanner_to_findings(&scanner_hits));

        // Clone the PR branch so the model can read context.
        let clone_opts = CloneOptions {
            host: self.provider.clone_host().to_string(),
            workspace: self.provider.workspace().to_string(),
            repo_slug: self.provider.repo_slug().to_string(),
            branch: pr.source_branch.clone(),
            username: self.provider.clone_username().to_string(),
            token: self.provider.clone_token().to_string(),
            depth: s.git_clone_depth,
            max_mb: s.git_clone_max_mb,
            timeout: Duration::from_secs_f64(s.git_clone_timeout_seconds),
            blob_filter: true,
        };
        let clone = match clone_pr_branch(&clone_opts).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("could not clone repo: {e}");
                result.summary =
                    "Automated review skipped — bugbot could not clone the PR branch. \
                                  Scanner findings (if any) are still posted."
                        .to_string();
                result.aborted = true;
                self.post(&mut result, &head_commit).await;
                return Ok(result);
            }
        };
        tracing::info!(
            "clone ready at {} @ {}",
            clone.path.display(),
            &clone.head_commit.chars().take(8).collect::<String>()
        );
        // SECURITY: scrub agent-instruction files from the untrusted clone.
        repo::scrub_injection_files(&clone.path);

        // Build the LLM input.
        let truncated = truncate_diff(&diff_text, s.max_diff_chars);
        let safe_diff = redact(&truncated);
        let files_block = render_changed_files(&files, &clone.path, s.max_file_chars);
        let safe_files_block = redact(&files_block);

        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert(
            "title",
            if pr.title.is_empty() {
                "(no title)".into()
            } else {
                pr.title.clone()
            },
        );
        vars.insert("author", pr.author.clone());
        vars.insert("source_branch", pr.source_branch.clone());
        vars.insert("destination_branch", pr.destination_branch.clone());
        vars.insert(
            "description",
            if pr.description.is_empty() {
                "_(no description)_".into()
            } else {
                pr.description.clone()
            },
        );
        vars.insert(
            "security_findings_block",
            format_security_block(&scanner_hits),
        );
        vars.insert("changed_files_block", safe_files_block);
        vars.insert("diff", safe_diff);
        vars.insert("repo_path", clone.path.to_string_lossy().into_owned());
        vars.insert("head_commit", clone.head_commit.clone());
        let user_prompt = render_template(prompts::USER, &vars);
        let system_prompt = prompts::render_system(domain);

        tracing::info!(
            "calling LLM ({} chars, cwd={}, domain={})",
            user_prompt.len(),
            clone.path.display(),
            domain
        );
        let req = LlmRequest {
            system_prompt,
            user_prompt,
            cwd: Some(clone.path.clone()),
            mode: LlmMode::Review,
            output_schema: Some(findings_schema()),
            timeout: self.review_timeout(),
        };
        let chat = match self.llm.run(&req).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("LLM review failed: {e}");
                result.summary = "Automated review failed: the LLM backend returned an error. \
                                  Scanner findings (if any) are still posted below."
                    .to_string();
                result.aborted = true;
                drop(clone);
                self.post(&mut result, &head_commit).await;
                return Ok(result);
            }
        };
        // Clone no longer needed for review parsing; drop to free the temp dir.
        drop(clone);
        result.usage = chat.usage;

        let payload = match parse_llm_json(&chat.content) {
            Ok(p) => p,
            Err(_) => {
                tracing::error!(
                    "LLM did not return valid JSON. content (redacted, 500): {}",
                    redact(&chat.content).chars().take(500).collect::<String>()
                );
                result.summary =
                    "Automated review failed: model did not return parsable JSON.".to_string();
                result.aborted = true;
                json!({ "summary": result.summary, "findings": [] })
            }
        };

        let (summary, llm_findings) = llm_findings_to_model(&payload);
        if !summary.is_empty() {
            result.summary = summary;
        } else if result.summary.is_empty() {
            result.summary = "Automated review complete.".to_string();
        }

        let valid = valid_lines_per_file(&files);
        let llm_findings = filter_findings_to_diff(llm_findings, &valid);
        result.findings.extend(llm_findings);
        result.findings = dedupe(std::mem::take(&mut result.findings));

        self.post(&mut result, &head_commit).await;
        tracing::info!(
            "review done — findings={} top={} tokens input={} cache_create={} cache_read={} output={} total={}",
            result.findings.len(),
            result.top_severity().as_str(),
            result.usage.input,
            result.usage.cache_creation,
            result.usage.cache_read,
            result.usage.output,
            result.usage.total()
        );
        Ok(result)
    }

    async fn post(&self, result: &mut ReviewResult, head_commit: &str) {
        let s = self.s;
        let marker = &s.bot_marker;
        let name = self.llm.display_name();
        let kind = if self.provider.clone_host().contains("github") {
            ProviderKind::GitHub
        } else {
            ProviderKind::Bitbucket
        };

        let already_files = if s.dry_run {
            HashSet::new()
        } else {
            match self.provider.list_comments(result.pr_id).await {
                Ok(existing) => already_commented_files(&existing, marker),
                Err(e) => {
                    tracing::warn!("could not list existing comments (idempotency): {e}");
                    HashSet::new()
                }
            }
        };

        let cap = s.max_inline_comments;
        let mut posted = 0usize;
        let groups = group_findings_by_file(&result.findings);
        'outer: for group in groups {
            if posted >= cap {
                tracing::info!("inline-comment cap reached ({cap}), stopping");
                break;
            }
            let file = group[0].file.clone();
            if already_files.contains(&file) {
                tracing::info!("skip already-commented file {file}");
                continue;
            }
            let with_suggestion: Vec<&Finding> =
                group.iter().filter(|f| f.suggestion.is_some()).collect();
            let without_suggestion: Vec<Finding> = group
                .iter()
                .filter(|f| f.suggestion.is_none())
                .cloned()
                .collect();

            for f in with_suggestion {
                if posted >= cap {
                    break 'outer;
                }
                let body = format_inline_body(f, &name, marker, kind);
                if s.dry_run {
                    println!(
                        "[DRY-RUN inline-suggestion] {}:{}\n{body}\n",
                        f.file, f.line
                    );
                } else {
                    let ic = InlineComment {
                        file: f.file.clone(),
                        line: f.line,
                        body,
                        commit_id: if head_commit.is_empty() {
                            None
                        } else {
                            Some(head_commit.to_string())
                        },
                        start_line: if kind == ProviderKind::GitHub {
                            f.suggestion_start_line
                        } else {
                            None
                        },
                    };
                    if let Err(e) = self.provider.post_inline_comment(result.pr_id, &ic).await {
                        tracing::warn!(
                            "failed to post inline suggestion on {}:{}: {e}",
                            f.file,
                            f.line
                        );
                        continue;
                    }
                }
                posted += 1;
            }

            if !without_suggestion.is_empty() && posted < cap {
                let anchor = &without_suggestion[0];
                let body = format_grouped_inline_body(&without_suggestion, &name, marker, kind);
                if s.dry_run {
                    println!(
                        "[DRY-RUN inline-grouped] {}@{} ({} findings)\n{body}\n",
                        file,
                        anchor.line,
                        without_suggestion.len()
                    );
                } else {
                    let ic = InlineComment {
                        file: file.clone(),
                        line: anchor.line,
                        body,
                        commit_id: if head_commit.is_empty() {
                            None
                        } else {
                            Some(head_commit.to_string())
                        },
                        start_line: None,
                    };
                    if let Err(e) = self.provider.post_inline_comment(result.pr_id, &ic).await {
                        tracing::warn!("failed to post grouped comment on {file}: {e}");
                    } else {
                        posted += 1;
                    }
                }
                if s.dry_run {
                    posted += 1;
                }
            }
        }
        result.posted_inline = posted;

        let summary_body = format_summary_body(result, &name, marker);
        if s.dry_run {
            println!("[DRY-RUN summary]\n{summary_body}\n");
        } else if let Err(e) = self
            .provider
            .post_summary_comment(result.pr_id, &summary_body)
            .await
        {
            tracing::warn!("failed to post summary comment: {e}");
        } else {
            result.posted_summary = true;
        }

        self.post_check_run(result, head_commit, kind, &summary_body)
            .await;
    }

    /// GitHub-only: surface the review as a Check Run (pass/fail icon next to
    /// CI) in addition to the comment. No-op on Bitbucket / dry-run / missing
    /// head sha.
    async fn post_check_run(
        &self,
        result: &ReviewResult,
        head_commit: &str,
        kind: ProviderKind,
        summary_body: &str,
    ) {
        if kind != ProviderKind::GitHub || head_commit.is_empty() {
            return;
        }
        let (conclusion, title) = check_run_conclusion(result, self.s.fail_on_severity);
        if self.s.dry_run {
            println!("[DRY-RUN check-run] conclusion={conclusion} title={title}\n");
            return;
        }
        if let Err(e) = self
            .provider
            .create_check_run(
                head_commit,
                "bugbot review",
                conclusion,
                &title,
                summary_body,
            )
            .await
        {
            tracing::warn!("failed to create check run: {e}");
        }
    }
}

/// Decide the Check Run `conclusion` + `output.title` for a finished (or
/// aborted) review. Split out from `post_check_run` so it's unit-testable
/// without needing a live `Reviewer`/`Provider`. `aborted` always wins over
/// `findings` being empty — a review that never ran must not read as
/// `neutral`/`success` on a required status check.
fn check_run_conclusion(result: &ReviewResult, fail_on: Severity) -> (&'static str, String) {
    if result.aborted {
        return ("failure", "Review did not complete".to_string());
    }
    if result.findings.is_empty() {
        // Nothing wrong at all — the best possible outcome — reads as a
        // green check, not a grey "neutral" dot.
        return ("success", "No findings".to_string());
    }
    let title = format!(
        "{} finding(s) — top severity: {}",
        result.findings.len(),
        result.top_severity().as_str()
    );
    if result.top_severity() >= fail_on {
        return ("failure", title);
    }
    // Findings exist but none are severe enough to block — informational,
    // worth a look, but shouldn't read as either a clean pass or a failure.
    ("neutral", title)
}

/// JSON artefact for the CLI `--artifact` / offline eval. Redacted.
pub fn result_to_json(result: &ReviewResult) -> String {
    let findings: Vec<Value> = result
        .findings
        .iter()
        .map(|f| {
            json!({
                "file": f.file,
                "line": f.line,
                "severity": f.severity.as_str(),
                "category": f.category,
                "title": f.title,
                "message": f.message,
                "source": match f.source { FindingSource::Scanner => "scanner", FindingSource::Llm => "llm" },
                "suggestion": f.suggestion,
                "suggestion_start_line": f.suggestion_start_line,
            })
        })
        .collect();
    let payload = json!({
        "pr_id": result.pr_id,
        "summary": result.summary,
        "top_severity": result.top_severity().as_str(),
        "input_tokens": result.usage.input,
        "cache_creation_tokens": result.usage.cache_creation,
        "cache_read_tokens": result.usage.cache_read,
        "output_tokens": result.usage.output,
        "total_tokens": result.usage.total(),
        "posted_inline": result.posted_inline,
        "posted_summary": result.posted_summary,
        "findings": findings,
    });
    redact(&serde_json::to_string_pretty(&payload).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(file: &str, line: u32, sev: Severity, sug: Option<&str>) -> Finding {
        Finding {
            file: file.into(),
            line,
            severity: sev,
            category: "correctness".into(),
            title: "test finding".into(),
            message: "msg".into(),
            source: FindingSource::Llm,
            suggestion: sug.map(str::to_string),
            suggestion_start_line: None,
        }
    }

    #[test]
    fn findings_schema_category_enum_matches_prompt() {
        // prompts/system.md documents this exact category list (including
        // in its own copy of the schema shown to the model) — codex gets
        // `findings_schema()` as strict --output-schema, so if this enum
        // falls behind the prompt's, the model can be told a category
        // exists that decode-time validation then rejects. Cursor Bugbot
        // and bugbot's own review both caught this drifting once already.
        let schema = findings_schema();
        let enum_values = schema["properties"]["findings"]["items"]["properties"]["category"]
            ["enum"]
            .as_array()
            .expect("category enum present")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "security",
            "correctness",
            "data-loss",
            "performance",
            "secret-leak",
            "maintainability",
        ] {
            assert!(
                enum_values.contains(&expected),
                "findings_schema() category enum missing {expected:?} — update it alongside prompts/system.md"
            );
        }
    }

    #[test]
    fn check_run_aborted_review_never_reads_as_passing() {
        // Clone/LLM failure: no findings surfaced, but the review never ran —
        // must be `failure`, not `neutral`/`success` (else a broken bugbot
        // silently green-lights a required status check).
        let aborted = ReviewResult {
            aborted: true,
            ..Default::default()
        };
        let (conclusion, title) = check_run_conclusion(&aborted, Severity::Critical);
        assert_eq!(conclusion, "failure");
        assert_eq!(title, "Review did not complete");
    }

    #[test]
    fn check_run_clean_review_is_success_not_neutral() {
        // Zero findings is the best outcome — it must read as a green
        // check, not a grey "neutral" dot (that's reserved for "found
        // something, not blocking").
        let clean = ReviewResult::default();
        let (conclusion, _) = check_run_conclusion(&clean, Severity::Critical);
        assert_eq!(conclusion, "success");
    }

    #[test]
    fn check_run_severity_gates_neutral_vs_failure() {
        let low = ReviewResult {
            findings: vec![f("a.rs", 1, Severity::Low, None)],
            ..Default::default()
        };
        assert_eq!(check_run_conclusion(&low, Severity::High).0, "neutral");

        let critical = ReviewResult {
            findings: vec![f("a.rs", 1, Severity::Critical, None)],
            ..Default::default()
        };
        assert_eq!(check_run_conclusion(&critical, Severity::High).0, "failure");
    }

    #[test]
    fn parse_llm_json_tolerates_fences() {
        let v = parse_llm_json("```json\n{\"summary\":\"s\",\"findings\":[]}\n```").unwrap();
        assert_eq!(v["summary"], "s");
    }

    #[test]
    fn snap_to_nearest_added_line() {
        let mut valid = HashMap::new();
        valid.insert("a.rs".to_string(), HashSet::from([10u32, 11, 12]));
        let got = filter_findings_to_diff(vec![f("a.rs", 13, Severity::High, None)], &valid);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].line, 12); // snapped from 13 -> 12 (within 3)
                                     // far away dropped
        let got2 = filter_findings_to_diff(vec![f("a.rs", 99, Severity::High, None)], &valid);
        assert!(got2.is_empty());
        // file not in diff dropped
        let got3 = filter_findings_to_diff(vec![f("zzz.rs", 10, Severity::High, None)], &valid);
        assert!(got3.is_empty());
    }

    #[test]
    fn dedupe_and_sort_scanner_first() {
        let mut findings = vec![
            f("b.rs", 5, Severity::Low, None),
            f("a.rs", 1, Severity::Critical, None),
        ];
        findings.push(Finding {
            source: FindingSource::Scanner,
            ..f("c.rs", 2, Severity::Low, None)
        });
        let out = dedupe(findings);
        assert_eq!(out[0].source, FindingSource::Scanner); // scanner first
        assert_eq!(out[1].severity, Severity::Critical); // then severity desc
    }

    #[test]
    fn github_suggestion_uses_suggestion_fence() {
        let body = format_inline_body(
            &f("a.rs", 1, Severity::High, Some("fixed = true")),
            "Codex",
            "bugbot:v1",
            ProviderKind::GitHub,
        );
        assert!(body.contains("```suggestion"));
        let bb = format_inline_body(
            &f("a.rs", 1, Severity::High, Some("fixed = true")),
            "Codex",
            "bugbot:v1",
            ProviderKind::Bitbucket,
        );
        assert!(bb.contains("_Suggested fix:_"));
        assert!(!bb.contains("```suggestion"));
    }

    #[test]
    fn render_template_does_not_rescan_inserted_values() {
        let mut vars = HashMap::new();
        vars.insert("diff", "contains {author} literally".to_string());
        vars.insert("author", "alice".to_string());
        let out = render_template("D={diff} A={author}", &vars);
        assert_eq!(out, "D=contains {author} literally A=alice");
    }
}
