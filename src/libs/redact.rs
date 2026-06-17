//! Defence-in-depth secret masking. Any string that may leave the process
//! (LLM prompt, log line, posted comment, error text) goes through `redact`.
//! Mirrors the Python `libs/redact.py` pattern set and order.

use std::sync::LazyLock;

use regex::Regex;

/// (pattern, replacement). Applied in order — order matters: the OpenRouter
/// `sk-or-v1-` rule runs before the generic `sk-` rule so it isn't
/// double-masked.
static PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let raw: &[(&str, &str)] = &[
        (r"AKIA[0-9A-Z]{16}", "AKIA****REDACTED****"),
        (r"ghp_[A-Za-z0-9]{30,}", "ghp_****REDACTED****"),
        (
            r"github_pat_[A-Za-z0-9_]{40,}",
            "github_pat_****REDACTED****",
        ),
        (r"glpat-[A-Za-z0-9\-_]{20,}", "glpat-****REDACTED****"),
        (r"xox[abprs]-[A-Za-z0-9-]{10,}", "xox*-****REDACTED****"),
        (r"sk-or-v1-[A-Za-z0-9]{20,}", "sk-or-v1-****REDACTED****"),
        (r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "sk-****REDACTED****"),
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY----- ****REDACTED**** -----END PRIVATE KEY-----",
        ),
        (
            r#"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"]?[^'"\s]{6,}"#,
            "${1}=****REDACTED****",
        ),
        (
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@",
            "${1}://****:****@",
        ),
        // Any URL with embedded basic-auth — covers git clone URLs.
        (r"(?i)(https?)://[^:\s/@]+:[^@\s/]+@", "${1}://****:****@"),
    ];
    raw.iter()
        .map(|(p, r)| (Regex::new(p).expect("redact pattern compiles"), *r))
        .collect()
});

/// Mask obvious secrets in `text`.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for (pat, repl) in PATTERNS.iter() {
        out = pat.replace_all(&out, *repl).into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn masks_cloud_and_vcs_keys() {
        assert!(redact("AKIAABCDEFGHIJKLMNOP").contains("AKIA****REDACTED****"));
        assert!(redact(&format!("ghp_{}", "a".repeat(36))).contains("ghp_****REDACTED****"));
    }

    #[test]
    fn masks_basic_auth_urls() {
        let got = redact("https://x-token-auth:supersecretvalue@bitbucket.org/ws/repo.git");
        assert!(
            got.contains("https://****:****@bitbucket.org/ws/repo.git"),
            "{got}"
        );
        assert!(!got.contains("supersecretvalue"));
    }

    #[test]
    fn masks_db_uri_creds() {
        let got = redact("postgres://user:p4ssw0rd@db.internal:5432/app");
        assert!(got.contains("postgres://****:****@"), "{got}");
        assert!(!got.contains("p4ssw0rd"));
    }

    #[test]
    fn masks_password_assignment() {
        let got = redact("password = \"hunter2hunter2\"");
        assert!(got.contains("****REDACTED****"), "{got}");
        assert!(!got.contains("hunter2hunter2"));
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let s = "just a normal line of code: let x = 1;";
        assert_eq!(redact(s), s);
    }
}
