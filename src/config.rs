//! Env-driven configuration (prefix `BUGBOT_`), ported from the Python
//! `config.py` and extended for the codex backend + GitHub interactivity.
//!
//! Loading: `.env` is read first (via `dotenvy`) into the process env, then
//! each field is pulled from `std::env`. We hand-roll the load (rather than a
//! config crate) so alias handling (`BITBUCKET_TOKEN`/`GITHUB_TOKEN`), the
//! secret newtype, and the cross-field validator stay fully explicit.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A string that never prints its contents in `Debug`/logs.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    /// Expose the raw secret. Call sites should keep the result short-lived
    /// and never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// 0..=4 — used for "meets/exceeds" comparisons and sorting. Derived
    /// `Ord` already orders the variants by declaration, but `rank()` keeps
    /// the call sites readable and mirrors the Python.
    pub fn rank(self) -> u8 {
        match self {
            Severity::None => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Severity::None),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which LLM CLI backend drives reviews. `codex` is the default/primary;
/// `claude` is kept as a selectable fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmBackendKind {
    Codex,
    Claude,
}

impl LlmBackendKind {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "codex" => Some(LlmBackendKind::Codex),
            "claude" => Some(LlmBackendKind::Claude),
            _ => None,
        }
    }
}

/// Where autofix commits land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixBranchStrategy {
    /// Push to a fresh `bugbot/fix-...` branch and open a PR (default, safest).
    NewBranch,
    /// Commit directly onto the PR's source branch.
    ExistingBranch,
}

impl FixBranchStrategy {
    fn parse(s: &str) -> Option<Self> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "newbranch" | "new" => Some(FixBranchStrategy::NewBranch),
            "existingbranch" | "existing" => Some(FixBranchStrategy::ExistingBranch),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid value for {key}: {msg}")]
    Invalid { key: &'static str, msg: String },
    #[error("{0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
pub struct Settings {
    // ---- LLM backend ----
    pub llm_backend: LlmBackendKind,

    // codex exec
    pub codex_cli_path: String,
    /// `None` → let codex use its entitled default (e.g. gpt-5.5).
    pub codex_model: Option<String>,
    /// `None` → don't pass model_reasoning_effort. one of low|medium|high.
    pub codex_reasoning_effort: Option<String>,
    pub codex_timeout_seconds: f64,

    // claude -p (fallback)
    pub claude_cli_path: String,
    pub claude_model: String,
    pub claude_effort: Option<String>,
    pub claude_timeout_seconds: f64,
    pub claude_allowed_tools: String,

    // ---- Bitbucket ----
    pub bitbucket_username: String,
    pub bitbucket_app_password: Option<Secret>,
    pub bitbucket_base_url: String,
    pub bitbucket_timeout_seconds: f64,

    // ---- GitHub ----
    pub github_token: Option<Secret>,
    pub github_webhook_secret: Option<Secret>,
    pub github_base_url: String,
    pub github_timeout_seconds: f64,
    pub github_webhook_path: String,
    /// Login of the account/app whose comments count as "ours" for
    /// reply-to-bot detection. Auto-detected via `GET /user` when unset.
    pub github_bot_login: Option<String>,

    // ---- git clone ----
    pub git_clone_depth: u32,
    pub git_clone_max_mb: u64,
    pub git_clone_timeout_seconds: f64,

    // ---- webhook server ----
    pub server_host: String,
    pub server_port: u16,
    pub webhook_path: String,
    pub webhook_secret: Option<Secret>,
    pub webhook_enforce_ip_allowlist: bool,
    pub webhook_ip_cache_seconds: u64,
    pub trust_forwarded_for: bool,
    pub max_concurrent_reviews: usize,

    // ---- review behaviour ----
    pub fail_on_severity: Severity,
    pub max_inline_comments: usize,
    pub max_diff_chars: usize,
    pub max_file_chars: usize,
    pub ignore_globs: String,
    pub dry_run: bool,
    pub bot_marker: String,
    pub default_domain: String,

    // ---- interactivity (GitHub) ----
    /// Handle issue_comment / pull_request_review_comment events (Q&A + commands).
    pub interactive_enabled: bool,
    /// Allow `@bugbot fix` to run codex in workspace-write mode and push.
    pub fix_enabled: bool,
    pub fix_max_per_pr_24h: u32,
    pub fix_branch_strategy: FixBranchStrategy,

    pub log_level: String,
}

impl Settings {
    pub fn bitbucket_enabled(&self) -> bool {
        self.bitbucket_app_password.is_some()
    }

    pub fn github_enabled(&self) -> bool {
        self.github_token.is_some()
    }

    pub fn ignore_glob_list(&self) -> Vec<String> {
        self.ignore_globs
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn claude_allowed_tools_list(&self) -> Vec<String> {
        self.claude_allowed_tools
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Load `.env` (best-effort) then read `BUGBOT_*` env, validate.
    pub fn load() -> Result<Settings, ConfigError> {
        let _ = dotenvy::dotenv();
        Self::from_env()
    }

    pub fn from_env() -> Result<Settings, ConfigError> {
        let s = Settings {
            llm_backend: env_enum(
                "BUGBOT_LLM_BACKEND",
                LlmBackendKind::Codex,
                LlmBackendKind::parse,
            )?,

            codex_cli_path: env_str_or("BUGBOT_CODEX_CLI_PATH", "codex"),
            codex_model: env_opt("BUGBOT_CODEX_MODEL"),
            codex_reasoning_effort: env_opt("BUGBOT_CODEX_REASONING_EFFORT"),
            codex_timeout_seconds: env_f64("BUGBOT_CODEX_TIMEOUT_SECONDS", 900.0)?,

            claude_cli_path: env_str_or("BUGBOT_CLAUDE_CLI_PATH", "claude"),
            claude_model: env_str_or("BUGBOT_CLAUDE_MODEL", "sonnet"),
            claude_effort: env_opt("BUGBOT_CLAUDE_EFFORT"),
            claude_timeout_seconds: env_f64("BUGBOT_CLAUDE_TIMEOUT_SECONDS", 600.0)?,
            claude_allowed_tools: env_str_or("BUGBOT_CLAUDE_ALLOWED_TOOLS", "Read,Grep,Glob"),

            bitbucket_username: env_str_or("BUGBOT_BITBUCKET_USERNAME", "x-token-auth"),
            bitbucket_app_password: env_secret(&[
                "BUGBOT_BITBUCKET_APP_PASSWORD",
                "BITBUCKET_TOKEN",
            ]),
            bitbucket_base_url: env_str_or(
                "BUGBOT_BITBUCKET_BASE_URL",
                "https://api.bitbucket.org/2.0",
            ),
            bitbucket_timeout_seconds: env_f64("BUGBOT_BITBUCKET_TIMEOUT_SECONDS", 60.0)?,

            github_token: env_secret(&["BUGBOT_GITHUB_TOKEN", "GITHUB_TOKEN"]),
            github_webhook_secret: env_secret(&["BUGBOT_GITHUB_WEBHOOK_SECRET"]),
            github_base_url: env_str_or("BUGBOT_GITHUB_BASE_URL", "https://api.github.com"),
            github_timeout_seconds: env_f64("BUGBOT_GITHUB_TIMEOUT_SECONDS", 60.0)?,
            github_webhook_path: env_str_or("BUGBOT_GITHUB_WEBHOOK_PATH", "/webhook/github"),
            github_bot_login: env_opt("BUGBOT_GITHUB_BOT_LOGIN"),

            git_clone_depth: env_u64("BUGBOT_GIT_CLONE_DEPTH", 50)? as u32,
            git_clone_max_mb: env_u64("BUGBOT_GIT_CLONE_MAX_MB", 512)?,
            git_clone_timeout_seconds: env_f64("BUGBOT_GIT_CLONE_TIMEOUT_SECONDS", 180.0)?,

            server_host: env_str_or("BUGBOT_SERVER_HOST", "0.0.0.0"),
            server_port: env_u64("BUGBOT_SERVER_PORT", 8080)? as u16,
            webhook_path: env_str_or("BUGBOT_WEBHOOK_PATH", "/webhook/bitbucket"),
            webhook_secret: env_secret(&["BUGBOT_WEBHOOK_SECRET"]),
            webhook_enforce_ip_allowlist: env_bool("BUGBOT_WEBHOOK_ENFORCE_IP_ALLOWLIST", true)?,
            webhook_ip_cache_seconds: env_u64("BUGBOT_WEBHOOK_IP_CACHE_SECONDS", 3600)?,
            trust_forwarded_for: env_bool("BUGBOT_TRUST_FORWARDED_FOR", false)?,
            max_concurrent_reviews: env_u64("BUGBOT_MAX_CONCURRENT_REVIEWS", 2)?.max(1) as usize,

            fail_on_severity: env_enum(
                "BUGBOT_FAIL_ON_SEVERITY",
                Severity::Critical,
                Severity::parse,
            )?,
            max_inline_comments: env_u64("BUGBOT_MAX_INLINE_COMMENTS", 20)? as usize,
            max_diff_chars: env_u64("BUGBOT_MAX_DIFF_CHARS", 120_000)? as usize,
            max_file_chars: env_u64("BUGBOT_MAX_FILE_CHARS", 200_000)? as usize,
            ignore_globs: env_str_or(
                "BUGBOT_IGNORE_GLOBS",
                "*.lock,*.min.js,*.map,vendor/**,node_modules/**,dist/**,build/**",
            ),
            dry_run: env_bool("BUGBOT_DRY_RUN", false)?,
            bot_marker: env_str_or("BUGBOT_BOT_MARKER", "bugbot:v1"),
            default_domain: env_str_or("BUGBOT_DEFAULT_DOMAIN", "general"),

            interactive_enabled: env_bool("BUGBOT_INTERACTIVE_ENABLED", true)?,
            fix_enabled: env_bool("BUGBOT_FIX_ENABLED", true)?,
            fix_max_per_pr_24h: env_u64("BUGBOT_FIX_MAX_PER_PR_24H", 3)? as u32,
            fix_branch_strategy: env_enum(
                "BUGBOT_FIX_BRANCH_STRATEGY",
                FixBranchStrategy::NewBranch,
                FixBranchStrategy::parse,
            )?,

            log_level: env_str_or("BUGBOT_LOG_LEVEL", "INFO"),
        };
        s.validate()?;
        Ok(s)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.bitbucket_enabled() && !self.github_enabled() {
            return Err(ConfigError::Validation(
                "No PR provider configured. Set BUGBOT_BITBUCKET_APP_PASSWORD \
                 (or BITBUCKET_TOKEN) and/or BUGBOT_GITHUB_TOKEN."
                    .into(),
            ));
        }
        if self.bitbucket_enabled() && self.webhook_secret.is_none() {
            return Err(ConfigError::Validation(
                "BUGBOT_WEBHOOK_SECRET is required when Bitbucket is enabled.".into(),
            ));
        }
        if self.github_enabled() && self.github_webhook_secret.is_none() {
            return Err(ConfigError::Validation(
                "BUGBOT_GITHUB_WEBHOOK_SECRET is required when GitHub is enabled.".into(),
            ));
        }
        Ok(())
    }
}

// ---- env helpers ----------------------------------------------------------

fn env_opt(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

fn env_str_or(key: &str, default: &str) -> String {
    env_opt(key).unwrap_or_else(|| default.to_string())
}

fn env_secret(keys: &[&str]) -> Option<Secret> {
    keys.iter().find_map(|k| env_opt(k)).map(Secret::new)
}

fn env_bool(key: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env_opt(key) {
        None => Ok(default),
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                key,
                msg: format!("expected a boolean, got {other:?}"),
            }),
        },
    }
}

fn env_u64(key: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env_opt(key) {
        None => Ok(default),
        Some(v) => v.trim().parse::<u64>().map_err(|e| ConfigError::Invalid {
            key,
            msg: format!("expected an integer, got {v:?} ({e})"),
        }),
    }
}

fn env_f64(key: &'static str, default: f64) -> Result<f64, ConfigError> {
    match env_opt(key) {
        None => Ok(default),
        Some(v) => v.trim().parse::<f64>().map_err(|e| ConfigError::Invalid {
            key,
            msg: format!("expected a number, got {v:?} ({e})"),
        }),
    }
}

fn env_enum<T>(
    key: &'static str,
    default: T,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<T, ConfigError> {
    match env_opt(key) {
        None => Ok(default),
        Some(v) => parse(&v).ok_or_else(|| ConfigError::Invalid {
            key,
            msg: format!("unrecognised value {v:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Low);
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("nope"), None);
        assert_eq!(Severity::High.rank(), 3);
        assert_eq!(Severity::Medium.as_str(), "medium");
    }

    #[test]
    fn secret_debug_is_masked() {
        let s = Secret::new("super-secret-token");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "super-secret-token");
    }

    #[test]
    fn fix_branch_strategy_parse() {
        assert_eq!(
            FixBranchStrategy::parse("new-branch"),
            Some(FixBranchStrategy::NewBranch)
        );
        assert_eq!(
            FixBranchStrategy::parse("existing"),
            Some(FixBranchStrategy::ExistingBranch)
        );
    }
}
