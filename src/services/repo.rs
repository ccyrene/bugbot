//! Sandboxed shallow git clone of the PR source branch. Ported from
//! `services/repo.py`. We shell out to the real `git` binary (libgit2 can't do
//! `--filter=blob:limit` partial clone nor honour `GIT_CONFIG_GLOBAL=/dev/null`
//! hermeticity). The clone lives in a `TempDir` that RAII-removes on drop —
//! the Rust equivalent of the Python `finally: rm -rf`.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use tokio::process::Command;

use crate::libs::redact::redact;

#[derive(Debug, thiserror::Error)]
pub enum GitCloneError {
    #[error("git is not installed / not invokable: {0}")]
    GitMissing(String),
    #[error("git {op} timed out after {secs}s")]
    Timeout { op: &'static str, secs: u64 },
    #[error("git {op} failed ({code}): {stderr}")]
    Failed {
        op: &'static str,
        code: i32,
        stderr: String,
    },
    #[error("clone too large: {size_mb} MB > limit {max_mb} MB")]
    TooLarge { size_mb: u64, max_mb: u64 },
}

#[derive(Debug, Clone)]
pub struct CloneOptions {
    pub host: String,
    pub workspace: String,
    pub repo_slug: String,
    pub branch: String,
    pub username: String,
    pub token: String,
    pub depth: u32,
    pub max_mb: u64,
    pub timeout: Duration,
    /// Review clones use `--filter=blob:limit=1m` for speed. The fix flow needs
    /// real blobs (to commit + push), so it clones with `blob_filter = false`.
    pub blob_filter: bool,
}

/// A cloned repo. The working tree is at `path`; the owned `TempDir` removes
/// everything (even on panic / error / early return) when this drops.
pub struct ClonedRepo {
    _tmp: tempfile::TempDir,
    pub path: PathBuf,
    pub head_commit: String,
}

fn clone_url(host: &str, workspace: &str, repo_slug: &str, username: &str, token: &str) -> String {
    let user = utf8_percent_encode(username, NON_ALPHANUMERIC).to_string();
    let pw = utf8_percent_encode(token, NON_ALPHANUMERIC).to_string();
    format!("https://{user}:{pw}@{host}/{workspace}/{repo_slug}.git")
}

/// Run a git command with the hardened, hermetic environment used for every
/// git invocation in bugbot. `extra_env` layers on top (e.g. commit identity).
pub async fn run_git(
    op: &'static str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
    timeout: Duration,
) -> Result<Output, GitCloneError> {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Hermetic: no pager, never prompt for creds, ignore host/user gitconfig
        // (which can carry credential.helper, hooks, etc.).
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/echo")
        .env("PAGER", "cat")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            GitCloneError::GitMissing(e.to_string())
        } else {
            GitCloneError::Failed {
                op,
                code: -1,
                stderr: e.to_string(),
            }
        }
    })?;

    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(GitCloneError::Failed {
                op,
                code: -1,
                stderr: e.to_string(),
            })
        }
        // Future dropped on timeout → kill_on_drop reaps the child.
        Err(_elapsed) => {
            return Err(GitCloneError::Timeout {
                op,
                secs: timeout.as_secs(),
            })
        }
    };

    if !output.status.success() {
        let stderr = redact(&String::from_utf8_lossy(&output.stderr));
        let trimmed: String = stderr.trim().chars().take(500).collect();
        return Err(GitCloneError::Failed {
            op,
            code: output.status.code().unwrap_or(-1),
            stderr: trimmed,
        });
    }
    Ok(output)
}

fn dir_size_mb(path: &Path) -> u64 {
    fn walk(p: &Path, acc: &mut u64) {
        let Ok(rd) = std::fs::read_dir(p) else {
            return;
        };
        for entry in rd.flatten() {
            match entry.file_type() {
                // file_type() does NOT follow symlinks → no symlink loops.
                Ok(ft) if ft.is_dir() => walk(&entry.path(), acc),
                Ok(ft) if ft.is_file() => {
                    if let Ok(m) = entry.metadata() {
                        *acc += m.len();
                    }
                }
                _ => {}
            }
        }
    }
    let mut total = 0u64;
    walk(path, &mut total);
    total / (1024 * 1024)
}

/// Clone the PR's source branch into a fresh temp dir. The returned
/// `ClonedRepo` owns the temp dir; drop it to clean up.
pub async fn clone_pr_branch(opts: &CloneOptions) -> Result<ClonedRepo, GitCloneError> {
    let tmp = tempfile::Builder::new()
        .prefix("bugbot-clone-")
        .tempdir()
        .map_err(|e| GitCloneError::Failed {
            op: "mkdtemp",
            code: -1,
            stderr: e.to_string(),
        })?;
    let repo_path = tmp.path().join("repo");

    let url = clone_url(
        &opts.host,
        &opts.workspace,
        &opts.repo_slug,
        &opts.username,
        &opts.token,
    );
    let depth = opts.depth.to_string();
    let repo_path_str = repo_path.to_string_lossy().to_string();
    let mut args: Vec<&str> = vec![
        "clone",
        "--depth",
        &depth,
        "--single-branch",
        "--branch",
        &opts.branch,
        "--no-tags",
    ];
    if opts.blob_filter {
        args.push("--filter=blob:limit=1m");
    }
    args.push(&url);
    args.push(&repo_path_str);

    tracing::debug!(
        "git {}",
        redact(&format!(
            "clone --depth {depth} --branch {} {}",
            opts.branch, url
        ))
    );

    run_git("clone", &args, None, &[], opts.timeout).await?;

    let size_mb = dir_size_mb(&repo_path);
    if size_mb > opts.max_mb {
        return Err(GitCloneError::TooLarge {
            size_mb,
            max_mb: opts.max_mb,
        });
    }
    tracing::info!(
        "cloned {}/{}@{} ({} MB)",
        opts.workspace,
        opts.repo_slug,
        opts.branch,
        size_mb
    );

    let head = run_git(
        "rev-parse",
        &["rev-parse", "HEAD"],
        Some(&repo_path),
        &[],
        Duration::from_secs(10),
    )
    .await
    .ok();
    let head_commit = head
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    Ok(ClonedRepo {
        _tmp: tmp,
        path: repo_path,
        head_commit,
    })
}

/// Remove files an LLM agent treats as instructions, before running the model
/// over an UNTRUSTED clone. Defence in depth alongside codex's
/// `-c project_doc_max_bytes=0`; also covers the claude backend (which honours
/// CLAUDE.md / AGENTS.md from cwd). Walks the whole tree; does not follow
/// symlinks (so it can't escape the clone).
pub fn scrub_injection_files(root: &Path) {
    const FILE_NAMES: &[&str] = &[
        "AGENTS.md",
        "AGENTS.override.md",
        "CLAUDE.md",
        ".cursorrules",
    ];
    const DIR_NAMES: &[&str] = &[".cursor"];

    fn walk(dir: &Path) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() {
                if DIR_NAMES.iter().any(|d| name == *d) {
                    let _ = std::fs::remove_dir_all(entry.path());
                } else {
                    walk(&entry.path());
                }
            } else if ft.is_file() && FILE_NAMES.iter().any(|f| name == *f) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    walk(root);
    let _ = std::fs::remove_file(root.join(".github/copilot-instructions.md"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_removes_injection_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("AGENTS.md"), "evil").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/CLAUDE.md"), "evil").unwrap();
        std::fs::create_dir_all(root.join(".cursor")).unwrap();
        std::fs::write(root.join(".cursor/rules"), "evil").unwrap();
        std::fs::write(root.join("keep.rs"), "ok").unwrap();

        scrub_injection_files(root);

        assert!(!root.join("AGENTS.md").exists());
        assert!(!root.join("sub/CLAUDE.md").exists());
        assert!(!root.join(".cursor").exists());
        assert!(root.join("keep.rs").exists());
    }

    #[test]
    fn clone_url_encodes_credentials() {
        let u = clone_url(
            "github.com",
            "acme",
            "widget",
            "x-access-token",
            "tok/with:special@chars",
        );
        assert!(u.starts_with("https://x%2Daccess%2Dtoken:"));
        assert!(u.contains("@github.com/acme/widget.git"));
        // the special chars in the token must be percent-encoded, not raw
        assert!(!u.contains("tok/with:special@chars"));
    }

    #[tokio::test]
    async fn run_git_reports_failure() {
        // `git` exists on the test host; an invalid subcommand exits non-zero.
        let res = run_git(
            "bogus",
            &["definitely-not-a-git-command"],
            None,
            &[],
            Duration::from_secs(10),
        )
        .await;
        assert!(matches!(res, Err(GitCloneError::Failed { .. })));
    }
}
