//! Logging setup via `tracing` (replaces loguru). Honors `RUST_LOG` if set,
//! otherwise falls back to the configured level (`BUGBOT_LOG_LEVEL`).
//! Timestamps render at a fixed UTC offset (`BUGBOT_LOG_UTC_OFFSET_HOURS`,
//! default 0 = UTC) — a fixed offset avoids the multithreaded local-time
//! detection footgun in `time`.

use time::format_description::well_known::Rfc3339;
use time::UtcOffset;
use tracing_subscriber::fmt::time::OffsetTime;
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
/// `utc_offset_hours` shifts log timestamps (e.g. 7 → `+07:00`); out-of-range
/// values fall back to UTC.
pub fn init(level: &str, utc_offset_hours: i8) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level_directive(level)));
    let offset = UtcOffset::from_hms(utc_offset_hours, 0, 0).unwrap_or(UtcOffset::UTC);
    let timer = OffsetTime::new(offset, Rfc3339);
    let _ = fmt()
        .with_env_filter(filter)
        .with_timer(timer)
        .with_target(true)
        .with_level(true)
        .try_init();
}
