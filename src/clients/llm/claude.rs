//! `claude -p` backend (fallback). Ports `clients/claude_cli.py`.
//!
//! Read-only review/reply only — the allowed-tools guard refuses
//! Bash/Edit/Write, so `Fix` mode is unsupported here (use the codex backend).

use serde_json::Value;

use super::{run_cli, LlmError, LlmMode, LlmRequest, LlmResponse, TokenUsage};

const FORBIDDEN_TOOLS: &[&str] = &["Bash", "Edit", "Write", "MultiEdit", "WebFetch"];
const VALID_EFFORT: &[&str] = &["low", "medium", "high", "xhigh", "max"];

pub struct ClaudeBackend {
    cli_path: String,
    model: String,
    effort: Option<String>,
    allowed_tools: Vec<String>,
}

impl ClaudeBackend {
    pub fn new(
        cli_path: &str,
        model: String,
        effort: Option<String>,
        allowed_tools: Vec<String>,
    ) -> Result<Self, LlmError> {
        // Last line of defence: never allow state-changing tools on untrusted PR code.
        let bad: Vec<&String> = allowed_tools
            .iter()
            .filter(|t| FORBIDDEN_TOOLS.contains(&t.as_str()))
            .collect();
        if !bad.is_empty() {
            return Err(LlmError::Unsupported(format!(
                "refusing dangerous tools in PR review: {bad:?}"
            )));
        }
        if let Some(e) = &effort {
            if !VALID_EFFORT.contains(&e.as_str()) {
                return Err(LlmError::Unsupported(format!(
                    "invalid claude effort: {e:?}"
                )));
            }
        }
        let tools = if allowed_tools.is_empty() {
            vec!["Read".into(), "Grep".into(), "Glob".into()]
        } else {
            allowed_tools
        };
        Ok(ClaudeBackend {
            cli_path: cli_path.to_string(),
            model,
            effort,
            allowed_tools: tools,
        })
    }

    pub fn display_name(&self) -> String {
        reviewer_display_name(&self.model)
    }

    pub async fn run(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        if req.mode == LlmMode::Fix {
            return Err(LlmError::Unsupported(
                "fix mode requires the codex backend (claude path is read-only)".into(),
            ));
        }

        let mut args: Vec<String> = vec![
            "-p".into(),
            "--output-format".into(),
            "json".into(),
            "--model".into(),
            self.model.clone(),
            "--append-system-prompt".into(),
            req.system_prompt.clone(),
            "--allowed-tools".into(),
            self.allowed_tools.join(","),
            "--permission-mode".into(),
            "default".into(),
        ];
        if let Some(e) = &self.effort {
            args.push("--effort".into());
            args.push(e.clone());
        }

        // claude runs with cwd = the clone so Read/Grep/Glob resolve there.
        let out = run_cli(
            "claude",
            &self.cli_path,
            &args,
            &req.user_prompt,
            req.cwd.as_deref(),
            req.timeout,
        )
        .await?;

        if !out.success {
            let stderr: String = crate::libs::redact::redact(out.stderr.trim())
                .chars()
                .take(500)
                .collect();
            return Err(LlmError::NonZero {
                backend: "claude",
                code: out.code,
                stderr,
            });
        }
        parse_envelope(&out.stdout)
    }
}

fn parse_envelope(stdout: &str) -> Result<LlmResponse, LlmError> {
    let envelope: Value =
        serde_json::from_str(stdout.trim()).map_err(|_| LlmError::EmptyOutput {
            backend: "claude",
            detail: format!(
                "did not return JSON; first 200 chars: {:?}",
                crate::libs::redact::redact(stdout)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
        })?;
    if envelope
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let msg = envelope
            .get("result")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(LlmError::NonZero {
            backend: "claude",
            code: 1,
            stderr: crate::libs::redact::redact(msg).chars().take(500).collect(),
        });
    }
    let content = envelope
        .get("result")
        .and_then(Value::as_str)
        .or_else(|| envelope.get("text").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let usage = envelope.get("usage").cloned().unwrap_or(Value::Null);
    let g = |k: &str| usage.get(k).and_then(Value::as_u64).unwrap_or(0);
    Ok(LlmResponse {
        content,
        usage: TokenUsage {
            input: g("input_tokens"),
            cache_creation: g("cache_creation_input_tokens"),
            cache_read: g("cache_read_input_tokens"),
            output: g("output_tokens"),
        },
    })
}

/// Human-readable reviewer name (ported from the Python `reviewer_display_name`).
pub fn reviewer_display_name(model: &str) -> String {
    let m = model.trim().to_ascii_lowercase();
    if matches!(m.as_str(), "sonnet" | "opus" | "haiku") {
        let mut c = m.chars();
        let cap = c
            .next()
            .map(|f| f.to_uppercase().collect::<String>() + c.as_str());
        return format!("Claude {}", cap.unwrap_or(m.clone()));
    }
    if let Some(rest) = m.strip_prefix("claude-") {
        let parts: Vec<&str> = rest.split('-').collect();
        if parts.is_empty() {
            return "Claude".into();
        }
        let family = {
            let mut c = parts[0].chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        };
        let version = parts[1..].join(".");
        if version.is_empty() {
            format!("Claude {family}")
        } else {
            format!("Claude {family} {version}")
        }
    } else {
        "Claude".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names() {
        assert_eq!(reviewer_display_name("sonnet"), "Claude Sonnet");
        assert_eq!(reviewer_display_name("claude-opus-4-7"), "Claude Opus 4.7");
        assert_eq!(reviewer_display_name("weird-model"), "Claude");
    }

    #[test]
    fn rejects_dangerous_tools() {
        let r = ClaudeBackend::new(
            "claude",
            "sonnet".into(),
            None,
            vec!["Read".into(), "Bash".into()],
        );
        assert!(r.is_err());
    }

    #[test]
    fn parses_envelope() {
        let stdout = r#"{"type":"result","subtype":"success","is_error":false,"result":"hello","usage":{"input_tokens":10,"cache_read_input_tokens":5,"output_tokens":3}}"#;
        let resp = parse_envelope(stdout).unwrap();
        assert_eq!(resp.content, "hello");
        assert_eq!(resp.usage.input, 10);
        assert_eq!(resp.usage.cache_read, 5);
        assert_eq!(resp.usage.output, 3);
    }
}
