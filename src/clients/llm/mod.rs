//! LLM CLI backends. `codex exec` is the default/primary; `claude -p` is a
//! selectable fallback. Enum dispatch (no `dyn`/`async-trait`).

pub mod claude;
pub mod codex;

use std::path::PathBuf;
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
}

impl LlmBackend {
    pub fn from_settings(s: &Settings) -> Result<Self, LlmError> {
        match s.llm_backend {
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
        }
    }

    /// Human-readable reviewer name for the attribution footer.
    pub fn display_name(&self) -> String {
        match self {
            LlmBackend::Codex(b) => b.display_name(),
            LlmBackend::Claude(b) => b.display_name(),
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
