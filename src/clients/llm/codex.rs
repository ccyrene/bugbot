//! `codex exec` backend (default). Verified against codex-cli 0.132.0.
//!
//! Contract (all empirically confirmed):
//!   * prompt via stdin (`-` positional) — keeps the diff/secrets out of argv
//!   * `-s read-only` for review/reply, `workspace-write` for fix
//!   * `--output-schema FILE` + `-o FILE` → strict JSON in the file (review)
//!   * `-c project_doc_max_bytes=0` → neutralises AGENTS.md prompt-injection
//!     from untrusted clones (verified: planted canary disappears)
//!   * `--ephemeral --ignore-user-config --skip-git-repo-check` → hermetic
//!   * `--json` → JSONL events on stdout; token usage in the turn-completed
//!     event (best-effort parse)
//!   * codex enforces no timeout of its own → we wrap with our own.

use serde_json::Value;
use tokio::fs;

use super::{get_u64, run_cli, LlmError, LlmRequest, LlmResponse, TokenUsage};

pub struct CodexBackend {
    cli_path: String,
    model: Option<String>,
    reasoning_effort: Option<String>,
}

impl CodexBackend {
    pub fn new(
        cli_path: &str,
        model: Option<String>,
        reasoning_effort: Option<String>,
    ) -> Result<Self, LlmError> {
        Ok(CodexBackend {
            cli_path: cli_path.to_string(),
            model,
            reasoning_effort,
        })
    }

    pub fn display_name(&self) -> String {
        match &self.model {
            Some(m) => format!("Codex · {m}"),
            None => "Codex".to_string(),
        }
    }

    pub async fn run(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        // Per-run scratch dir for the schema + final-message files. RAII-cleaned.
        let scratch = tempfile::Builder::new()
            .prefix("bugbot-codex-")
            .tempdir()
            .map_err(|e| LlmError::Other {
                backend: "codex",
                source: anyhow::anyhow!("scratch dir: {e}"),
            })?;
        let out_file = scratch.path().join("out.txt");
        let schema_file = scratch.path().join("schema.json");

        let mut args: Vec<String> = vec!["exec".into()];
        if let Some(m) = &self.model {
            args.push("-m".into());
            args.push(m.clone());
        }
        args.push("-s".into());
        args.push(if req.mode.writable() {
            "workspace-write".into()
        } else {
            "read-only".into()
        });
        if let Some(cwd) = &req.cwd {
            args.push("-C".into());
            args.push(cwd.to_string_lossy().into_owned());
        }
        args.push("--skip-git-repo-check".into());
        args.push("--ephemeral".into());
        args.push("--ignore-user-config".into());
        // SECURITY: stop codex ingesting untrusted-repo AGENTS.md / project docs.
        args.push("-c".into());
        args.push("project_doc_max_bytes=0".into());
        if let Some(effort) = &self.reasoning_effort {
            args.push("-c".into());
            args.push(format!("model_reasoning_effort={effort}"));
        }
        if let Some(schema) = &req.output_schema {
            fs::write(
                &schema_file,
                serde_json::to_vec_pretty(schema).unwrap_or_default(),
            )
            .await
            .map_err(|e| LlmError::Other {
                backend: "codex",
                source: anyhow::anyhow!("write schema: {e}"),
            })?;
            args.push("--output-schema".into());
            args.push(schema_file.to_string_lossy().into_owned());
        }
        args.push("-o".into());
        args.push(out_file.to_string_lossy().into_owned());
        args.push("--json".into());
        args.push("--color".into());
        args.push("never".into());
        args.push("-".into());

        // codex has no system-prompt flag; fold persona + task into one prompt.
        let prompt = format!("{}\n\n{}", req.system_prompt.trim(), req.user_prompt);

        tracing::debug!(
            "codex exec: model={:?} mode={:?} schema={} cwd={:?} stdin_chars={}",
            self.model,
            req.mode,
            req.output_schema.is_some(),
            req.cwd,
            prompt.len()
        );

        // codex uses `-C <cwd>`, so no process cwd needed.
        let out = run_cli("codex", &self.cli_path, &args, &prompt, None, req.timeout).await?;
        if !out.success {
            let stderr: String = crate::libs::redact::redact(out.stderr.trim())
                .chars()
                .take(800)
                .collect();
            return Err(LlmError::NonZero {
                backend: "codex",
                code: out.code,
                stderr,
            });
        }

        // The final message lands in the -o file. On abort it's missing/empty.
        let content = match fs::read_to_string(&out_file).await {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                // Fallback: try to recover the final agent message from --json.
                match last_agent_message(&out.stdout) {
                    Some(s) if !s.trim().is_empty() => s.trim().to_string(),
                    _ => {
                        return Err(LlmError::EmptyOutput {
                            backend: "codex",
                            detail: "no final message in -o file or JSONL stream".into(),
                        })
                    }
                }
            }
        };

        let usage = parse_usage(&out.stdout);
        Ok(LlmResponse { content, usage })
    }
}

/// Best-effort token accounting from the `--json` event stream. codex (on a
/// ChatGPT subscription) isn't per-token billed, so this is informational —
/// absence is not an error.
fn parse_usage(stdout: &str) -> TokenUsage {
    let mut usage = TokenUsage::default();
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(u) = find_usage(&v) {
            if let Some(n) = get_u64(u, &["input_tokens", "input"]) {
                usage.input = n;
            }
            if let Some(n) = get_u64(
                u,
                &["cached_input_tokens", "cache_read_input_tokens", "cached"],
            ) {
                usage.cache_read = n;
            }
            let out = get_u64(u, &["output_tokens", "output"]).unwrap_or(0);
            let reasoning =
                get_u64(u, &["reasoning_output_tokens", "reasoning_tokens"]).unwrap_or(0);
            if out + reasoning > 0 {
                usage.output = out + reasoning;
            }
        }
    }
    usage
}

/// Find a usage-bearing object: `v.usage`, a nested `v.msg.usage`, or `v`
/// itself if it carries token fields.
fn find_usage(v: &Value) -> Option<&Value> {
    if let Some(u) = v.get("usage") {
        if u.is_object() {
            return Some(u);
        }
    }
    if let Some(msg) = v.get("msg") {
        if let Some(u) = msg.get("usage") {
            if u.is_object() {
                return Some(u);
            }
        }
    }
    if v.get("input_tokens").is_some() || v.get("output_tokens").is_some() {
        return Some(v);
    }
    None
}

/// Pull the last agent/assistant message text out of the JSONL stream — a
/// fallback for when the `-o` file is unexpectedly empty.
fn last_agent_message(stdout: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for line in stdout.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        // Try common shapes: {type|item_type:"...agent_message...", text/message/content}
        let ty = v.get("type").and_then(Value::as_str).unwrap_or("");
        let item_ty = v.get("item_type").and_then(Value::as_str).unwrap_or("");
        let is_msg = [ty, item_ty]
            .iter()
            .any(|s| s.contains("message") || s.contains("agent"));
        let text = v
            .get("text")
            .and_then(Value::as_str)
            .or_else(|| v.get("message").and_then(Value::as_str))
            .or_else(|| v.get("content").and_then(Value::as_str))
            .or_else(|| {
                v.get("msg")
                    .and_then(|m| m.get("text"))
                    .and_then(Value::as_str)
            });
        if is_msg {
            if let Some(t) = text {
                found = Some(t.to_string());
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usage_from_turn_completed() {
        let stdout = r#"{"type":"thread.started"}
{"type":"turn.completed","usage":{"input_tokens":1200,"cached_input_tokens":800,"output_tokens":300,"reasoning_output_tokens":50}}"#;
        let u = parse_usage(stdout);
        assert_eq!(u.input, 1200);
        assert_eq!(u.cache_read, 800);
        assert_eq!(u.output, 350);
        assert_eq!(u.total(), 1200 + 800 + 350);
    }

    #[test]
    fn usage_absent_is_zero_not_error() {
        let u = parse_usage("{\"type\":\"thread.started\"}\nnot json\n");
        assert_eq!(u.total(), 0);
    }

    #[test]
    fn recovers_agent_message_fallback() {
        let stdout =
            r#"{"type":"item.completed","item_type":"agent_message","text":"hello world"}"#;
        assert_eq!(last_agent_message(stdout).as_deref(), Some("hello world"));
    }
}
