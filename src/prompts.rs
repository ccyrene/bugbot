//! Prompt templates, embedded at compile time. The Python loaded these from
//! the package data dir + a filesystem focus loader with a path-traversal
//! guard; here they're `include_str!`'d and the focus set is a static
//! registry (adding a domain = drop a file in `prompts/focus/` + add a line
//! here + rebuild, mirroring the "rebuild to add a focus" model).

use std::sync::LazyLock;

use regex::Regex;

pub const SYSTEM: &str = include_str!("../prompts/system.md");
pub const USER: &str = include_str!("../prompts/user.md");
pub const REPLY: &str = include_str!("../prompts/reply.md");
pub const FIX: &str = include_str!("../prompts/fix.md");

const FOCUS_GENERAL: &str = include_str!("../prompts/focus/general.md");
const FOCUS_DATA_ENG: &str = include_str!("../prompts/focus/data-eng.md");
const FOCUS_ASR: &str = include_str!("../prompts/focus/asr.md");

static DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("domain regex compiles"));

/// The focus block for a domain, or `None` if unknown.
pub fn focus_block(domain: &str) -> Option<&'static str> {
    match domain {
        "general" => Some(FOCUS_GENERAL),
        "data-eng" => Some(FOCUS_DATA_ENG),
        "asr" => Some(FOCUS_ASR),
        _ => None,
    }
}

/// A domain is valid if it matches the safe-char regex AND is a known focus.
/// The regex isn't only cosmetic — it keeps obviously bogus URL segments out
/// of logs and error messages.
pub fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty() && DOMAIN_RE.is_match(domain) && focus_block(domain).is_some()
}

/// Load a domain's focus block, falling back to `general` (with a warning) for
/// unknown domains — the webhook layer should already have rejected those.
pub fn load_focus(domain: &str) -> &'static str {
    match focus_block(domain) {
        Some(block) => block,
        None => {
            tracing::warn!("unknown review domain {domain:?} — falling back to 'general'");
            FOCUS_GENERAL
        }
    }
}

/// Render the review system prompt for a domain (substitutes `{focus_block}`).
/// We use a plain string replace (not a format machinery) because the template
/// contains a literal `{...}` JSON schema that would otherwise need escaping.
pub fn render_system(domain: &str) -> String {
    SYSTEM.replace("{focus_block}", load_focus(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_domains_valid() {
        assert!(is_valid_domain("general"));
        assert!(is_valid_domain("data-eng"));
        assert!(is_valid_domain("asr"));
    }

    #[test]
    fn unknown_and_unsafe_domains_invalid() {
        assert!(!is_valid_domain("nope"));
        assert!(!is_valid_domain("../etc"));
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn render_system_substitutes_focus() {
        let rendered = render_system("general");
        assert!(!rendered.contains("{focus_block}"));
        assert!(rendered.contains("Security data leak"));
    }
}
