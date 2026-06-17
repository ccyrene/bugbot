//! Logging setup via `tracing` (replaces loguru). Honors `RUST_LOG` if set,
//! otherwise falls back to the configured level (`BUGBOT_LOG_LEVEL`).

use tracing_subscriber::{fmt, EnvFilter};

fn level_directive(level: &str) -> &'static str {
    match level.trim().to_ascii_uppercase().as_str() {
        "DEBUG" => "debug",
        "WARNING" | "WARN" => "warn",
        "ERROR" => "error",
        _ => "info",
    }
}

/// Initialise the global subscriber. Safe to call more than once (no-op after
/// the first); `try_init` swallows the "already set" error so tests don't panic.
pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level_directive(level)));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .try_init();
}
