//! LLM CLI backends. `codex exec` is the default/primary; `claude -p` is a
//! selectable fallback. Enum dispatch (no `dyn`/`async-trait`).

pub mod claude;
pub mod codex;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::config::{LlmBackendKind, Settings};

pub use claude::ClaudeBackend;
pub use codex::CodexBackend;

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("{0} CLI not found / not invokable: {1}")]
    CliNotFound(&'static str, String),
    #[error("{backend} CLI exited {code}: {stderr}")]
    NonZero {
        backend: &'static str,
        code: i32,
        stderr: String,
    },
    #[error("{0} CLI timed out after {1}s")]
    Timeout(&'static str, u64),
    #[error("{backend}: empty/missing output ({detail})")]
    EmptyOutput {
        backend: &'static str,
        detail: String,
    },
    #[error("{backend} backend: {source}")]
    Other {
        backend: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("{0}")]
    Unsupported(String),
}

/// What the LLM should do — controls sandbox + output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmMode {
    /// Read-only review; output constrained to the findings JSON schema.
    Review,
    /// Read-only conversational reply; free-text output.
    Reply,
    /// Workspace-write fix; the model edits files; free-text final message.
    Fix,
}

impl LlmMode {
    fn writable(self) -> bool {
        matches!(self, LlmMode::Fix)
    }
}

pub struct LlmRequest {
    pub system_prompt: String,
    pub user_prompt: String,
    pub cwd: Option<PathBuf>,
    pub mode: LlmMode,
    /// codex `--output-schema` (Review mode). Other backends ignore it and
    /// rely on the JSON instructions in the prompt.
    pub output_schema: Option<Value>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
    pub output: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input + self.cache_creation + self.cache_read + self.output
    }
}

pub struct LlmResponse {
    pub content: String,
    pub usage: TokenUsage,
}

pub enum LlmBackend {
    Codex(CodexBackend),
    Claude(ClaudeBackend),
    /// Try `primary`; on any non-timeout error, retry on `fallback`. Configured
    /// via `BUGBOT_LLM_BACKEND` + `BUGBOT_LLM_FALLBACK_BACKEND`.
    Failover {
        primary: Box<LlmBackend>,
        fallback: Box<LlmBackend>,
        /// 0 = primary produced the last response, 1 = fallback. Lets
        /// `display_name()` attribute to whichever backend actually ran. A
        /// fresh `LlmBackend` is built per job, so this never races.
        last_used: AtomicU8,
    },
}

/// Whether a primary-backend error should trigger failover to the secondary.
/// A timeout is deliberately NOT retried (the fallback would just burn another
/// full timeout window); every other error (quota exhausted, CLI failure,
/// unsupported mode, …) falls over.
fn should_failover(err: &LlmError) -> bool {
    !matches!(err, LlmError::Timeout(..))
}

impl LlmBackend {
    pub fn from_settings(s: &Settings) -> Result<Self, LlmError> {
        let primary = Self::build_kind(s.llm_backend, s)?;
        match s.llm_fallback_backend {
            Some(fb) if fb != s.llm_backend => Ok(LlmBackend::Failover {
                primary: Box::new(primary),
                fallback: Box::new(Self::build_kind(fb, s)?),
                last_used: AtomicU8::new(0),
            }),
            // No fallback, or fallback == primary → single backend.
            _ => Ok(primary),
        }
    }

    fn build_kind(kind: LlmBackendKind, s: &Settings) -> Result<Self, LlmError> {
        match kind {
            LlmBackendKind::Codex => Ok(LlmBackend::Codex(CodexBackend::new(
                &s.codex_cli_path,
                s.codex_model.clone(),
                s.codex_reasoning_effort.clone(),
            )?)),
            LlmBackendKind::Claude => Ok(LlmBackend::Claude(ClaudeBackend::new(
                &s.claude_cli_path,
                s.claude_model.clone(),
                s.claude_effort.clone(),
                s.claude_allowed_tools_list(),
            )?)),
        }
    }

    pub async fn run(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        match self {
            LlmBackend::Codex(b) => b.run(req).await,
            LlmBackend::Claude(b) => b.run(req).await,
            LlmBackend::Failover {
                primary,
                fallback,
                last_used,
            } => match Box::pin(primary.run(req)).await {
                Ok(resp) => {
                    last_used.store(0, Ordering::Relaxed);
                    Ok(resp)
                }
                Err(e) if should_failover(&e) => {
                    tracing::warn!(
                        "primary LLM ({}) failed: {e}; failing over to {}",
                        primary.display_name(),
                        fallback.display_name()
                    );
                    last_used.store(1, Ordering::Relaxed);
                    Box::pin(fallback.run(req)).await
                }
                Err(e) => Err(e),
            },
        }
    }

    /// Human-readable reviewer name for the attribution footer. For a failover
    /// backend this reflects whichever backend produced the last response.
    pub fn display_name(&self) -> String {
        match self {
            LlmBackend::Codex(b) => b.display_name(),
            LlmBackend::Claude(b) => b.display_name(),
            LlmBackend::Failover {
                primary,
                fallback,
                last_used,
            } => {
                if last_used.load(Ordering::Relaxed) == 0 {
                    primary.display_name()
                } else {
                    fallback.display_name()
                }
            }
        }
    }
}

// ---- shared subprocess runner --------------------------------------------

pub(crate) struct CliOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub success: bool,
}

/// Spawn `program args…`, feed `stdin_data` over stdin (concurrently, to avoid
/// pipe deadlock), and collect output under a hard timeout. `kill_on_drop`
/// reaps the child (and its Node grandchildren) if we time out.
pub(crate) async fn run_cli(
    backend: &'static str,
    program: &str,
    args: &[String],
    stdin_data: &str,
    cwd: Option<&std::path::Path>,
    timeout: Duration,
) -> Result<CliOutput, LlmError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            LlmError::CliNotFound(backend, format!("{program}: {e}"))
        } else {
            LlmError::Other {
                backend,
                source: anyhow::anyhow!("spawn failed: {e}"),
            }
        }
    })?;

    let stdin = child.stdin.take();
    let data = stdin_data.to_string();
    let writer = tokio::spawn(async move {
        if let Some(mut si) = stdin {
            let _ = si.write_all(data.as_bytes()).await;
            let _ = si.shutdown().await;
        }
    });

    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    let _ = writer.await;

    let output = match result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(LlmError::Other {
                backend,
                source: anyhow::anyhow!("wait failed: {e}"),
            })
        }
        Err(_elapsed) => return Err(LlmError::Timeout(backend, timeout.as_secs())),
    };

    Ok(CliOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code().unwrap_or(-1),
        success: output.status.success(),
    })
}

/// First `u64` found among `keys` in object `v`.
pub(crate) fn get_u64(v: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_triggers_on_every_error_except_timeout() {
        // Timeout must NOT fail over (avoid burning a second full window).
        assert!(!should_failover(&LlmError::Timeout("claude", 600)));
        // Everything else does (quota/exit-nonzero, empty, unsupported, missing CLI).
        assert!(should_failover(&LlmError::NonZero {
            backend: "claude",
            code: 1,
            stderr: "usage limit reached".into(),
        }));
        assert!(should_failover(&LlmError::Unsupported(
            "fix needs codex".into()
        )));
        assert!(should_failover(&LlmError::EmptyOutput {
            backend: "claude",
            detail: "no json".into(),
        }));
        assert!(should_failover(&LlmError::CliNotFound(
            "claude",
            "missing".into()
        )));
    }
}
