//! Secret / sensitive-data scanner over the **added lines** of a PR diff.
//! Ported from `services/security.py`. Goals, in order: (1) mandatory blocker
//! for HIGH/CRITICAL leaks, (2) never leak the raw value to the LLM, (3) low
//! false-positive rate via pattern + entropy + placeholder denylist.
//!
//! NOTE: Rust's `regex` crate has no look-around. The Python OpenAI-key rule
//! uses a negative lookahead `(?!ant-|or-v1-)`; we emulate it with the
//! `exclude_prefixes` post-filter so the dedicated anthropic / openrouter
//! rules own those keys.

use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::config::Severity;
use crate::services::diff::FileDiff;

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub file: String,
    pub line: u32,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    /// Already-masked excerpt, safe to render in comments / prompts.
    pub snippet: String,
    /// The original (sensitive!) match — kept ONLY for local use, never
    /// serialised.
    pub raw_match: String,
}

struct Rule {
    rule_id: &'static str,
    name: &'static str,
    severity: Severity,
    re: Regex,
    min_entropy: Option<f64>,
    use_placeholders: bool,
    exclude_prefixes: &'static [&'static str],
}

const PLACEHOLDER_TOKENS: &[&str] = &[
    "your-",
    "your_",
    "xxxx",
    "changeme",
    "change-me",
    "example",
    "placeholder",
    "redacted",
    "dummy",
    "fake-",
    "sample",
    "<",
    ">",
    "todo",
    "tbd",
    "n/a",
    "none",
    "null",
];

fn rule(rule_id: &'static str, name: &'static str, severity: Severity, pattern: &str) -> Rule {
    Rule {
        rule_id,
        name,
        severity,
        re: Regex::new(pattern).expect("scanner rule compiles"),
        min_entropy: None,
        use_placeholders: false,
        exclude_prefixes: &[],
    }
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // --- Cloud providers ---
        rule(
            "aws-access-key",
            "AWS Access Key ID",
            Severity::Critical,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        ),
        Rule {
            min_entropy: Some(4.0),
            ..rule(
                "aws-secret-key",
                "AWS Secret Access Key",
                Severity::Critical,
                r#"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,20}['"]([A-Za-z0-9/+=]{40})['"]"#,
            )
        },
        rule(
            "gcp-service-account",
            "GCP service account private key",
            Severity::Critical,
            r#""type"\s*:\s*"service_account""#,
        ),
        // --- Private keys ---
        rule(
            "private-key-pem",
            "PEM private key",
            Severity::Critical,
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        ),
        // --- VCS / CI tokens ---
        rule(
            "github-token",
            "GitHub personal access token",
            Severity::High,
            r"\bghp_[A-Za-z0-9]{30,}\b",
        ),
        rule(
            "github-fine-grained",
            "GitHub fine-grained PAT",
            Severity::High,
            r"\bgithub_pat_[A-Za-z0-9_]{40,}\b",
        ),
        rule(
            "gitlab-token",
            "GitLab PAT",
            Severity::High,
            r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        ),
        Rule {
            use_placeholders: false,
            ..rule(
                "bitbucket-app-password",
                "Bitbucket App Password (suspected)",
                Severity::High,
                r#"(?i)bitbucket[_-]?(?:app[_-]?password|token)\s*[:=]\s*['"]([A-Za-z0-9]{20,})['"]"#,
            )
        },
        // --- Chat / messaging ---
        rule(
            "slack-token",
            "Slack token",
            Severity::High,
            r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b",
        ),
        rule(
            "slack-webhook",
            "Slack incoming webhook",
            Severity::High,
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        ),
        rule(
            "discord-webhook",
            "Discord webhook",
            Severity::High,
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        ),
        rule(
            "telegram-bot-token",
            "Telegram bot token",
            Severity::High,
            r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b",
        ),
        // --- LLM providers ---
        Rule {
            // Emulates the Python negative lookahead (?!ant-|or-v1-).
            exclude_prefixes: &["sk-ant-", "sk-or-v1-"],
            ..rule(
                "openai-key",
                "OpenAI API key",
                Severity::Critical,
                r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            )
        },
        rule(
            "anthropic-key",
            "Anthropic API key",
            Severity::Critical,
            r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{30,}\b",
        ),
        rule(
            "openrouter-key",
            "OpenRouter API key",
            Severity::Critical,
            r"\bsk-or-v1-[A-Za-z0-9]{20,}\b",
        ),
        rule(
            "google-api-key",
            "Google API key",
            Severity::High,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
        ),
        // --- Generic high-signal ---
        rule(
            "jwt",
            "JSON Web Token (signed)",
            Severity::Medium,
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        ),
        rule(
            "db-url-with-creds",
            "Database URL with embedded credentials",
            Severity::Critical,
            r#"(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|clickhouse)://[^:\s/]+:[^@\s]+@[^\s'"]+"#,
        ),
        Rule {
            use_placeholders: true,
            ..rule(
                "password-assignment",
                "Hard-coded password assignment",
                Severity::High,
                r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]([^'"\s]{6,})['"]"#,
            )
        },
        Rule {
            use_placeholders: true,
            min_entropy: Some(3.0),
            ..rule(
                "secret-assignment",
                "Hard-coded secret/api key assignment",
                Severity::High,
                r#"(?i)(secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([^'"\s]{12,})['"]"#,
            )
        },
        rule(
            "basic-auth-url",
            "URL with basic auth credentials",
            Severity::High,
            r#"\bhttps?://[^/\s:@]+:[^/\s@]{4,}@[^\s'"]+"#,
        ),
        // --- PII (light touch) ---
        rule(
            "private-ipv4",
            "Private/internal IPv4 address",
            Severity::Low,
            r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b",
        ),
    ]
});

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let total = s.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

fn looks_like_placeholder(value: &str) -> bool {
    let low = value.to_ascii_lowercase();
    PLACEHOLDER_TOKENS.iter().any(|tok| low.contains(tok))
}

fn mask(value: &str) -> String {
    let len = value.chars().count();
    if len <= 8 {
        return "****".to_string();
    }
    let first3: String = value.chars().take(3).collect();
    let last2: String = value.chars().skip(len - 2).collect();
    format!("{first3}…{last2} ({len} chars)")
}

/// The most-secret-looking captured group: highest-index group that matched,
/// else the whole match.
fn candidate_value<'a>(caps: &Captures<'a>) -> &'a str {
    for i in (1..caps.len()).rev() {
        if let Some(m) = caps.get(i) {
            return m.as_str();
        }
    }
    caps.get(0).unwrap().as_str()
}

pub fn scan_line(file: &str, lineno: u32, content: &str) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    for r in RULES.iter() {
        for caps in r.re.captures_iter(content) {
            let whole = caps.get(0).unwrap().as_str();
            if r.exclude_prefixes.iter().any(|p| whole.starts_with(p)) {
                continue;
            }
            let value = candidate_value(&caps);
            if r.use_placeholders && looks_like_placeholder(value) {
                continue;
            }
            if let Some(min) = r.min_entropy {
                if shannon_entropy(value) < min {
                    continue;
                }
            }
            findings.push(SecretFinding {
                file: file.to_string(),
                line: lineno,
                rule_id: r.rule_id,
                rule_name: r.name,
                severity: r.severity,
                snippet: mask(value),
                raw_match: value.to_string(),
            });
        }
    }
    findings
}

pub fn scan_diff(files: &[FileDiff]) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    for f in files {
        if f.is_binary || f.is_deleted {
            continue;
        }
        for (lineno, content) in f.added_lines() {
            findings.extend(scan_line(f.path(), lineno, content));
        }
    }
    findings
}

pub fn highest_severity(findings: &[SecretFinding]) -> Severity {
    findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let f = scan_line("a.txt", 1, "key = AKIAABCDEFGHIJKLMNOP");
        assert!(f
            .iter()
            .any(|x| x.rule_id == "aws-access-key" && x.severity == Severity::Critical));
    }

    #[test]
    fn openai_key_excludes_anthropic_and_openrouter() {
        // anthropic key must NOT be flagged as openai-key (only anthropic-key).
        let ant = format!("token = sk-ant-api03-{}", "a".repeat(40));
        let f = scan_line("a.txt", 1, &ant);
        assert!(f.iter().any(|x| x.rule_id == "anthropic-key"));
        assert!(!f.iter().any(|x| x.rule_id == "openai-key"));

        // a plain openai key IS flagged as openai-key.
        let oai = format!("token = sk-{}", "A1b2C3d4".repeat(4));
        let f2 = scan_line("a.txt", 1, &oai);
        assert!(f2.iter().any(|x| x.rule_id == "openai-key"));
    }

    #[test]
    fn placeholder_password_is_skipped() {
        let f = scan_line("a.txt", 1, r#"password = "changeme""#);
        assert!(!f.iter().any(|x| x.rule_id == "password-assignment"));
        let f2 = scan_line("a.txt", 1, r#"password = "Tr0ub4dor&3xy""#);
        assert!(f2.iter().any(|x| x.rule_id == "password-assignment"));
    }

    #[test]
    fn detects_db_url_with_creds() {
        let f = scan_line("a.txt", 1, "DB=postgres://user:p4ssw0rd@db.host:5432/app");
        assert!(f.iter().any(|x| x.rule_id == "db-url-with-creds"));
    }

    #[test]
    fn detects_pem_private_key() {
        let f = scan_line("a.txt", 1, "-----BEGIN RSA PRIVATE KEY-----");
        assert!(f.iter().any(|x| x.rule_id == "private-key-pem"));
    }

    #[test]
    fn mask_hides_value() {
        let m = mask("AKIAABCDEFGHIJKLMNOP");
        assert!(m.contains("chars)"));
        assert!(!m.contains("ABCDEFGHIJKLMNOP"));
        assert_eq!(mask("short"), "****");
    }

    #[test]
    fn private_ip_is_low() {
        let f = scan_line("a.txt", 1, "host = 10.0.0.5");
        assert!(f
            .iter()
            .any(|x| x.rule_id == "private-ipv4" && x.severity == Severity::Low));
    }

    #[test]
    fn highest_severity_picks_critical() {
        let f = scan_line("a.txt", 1, "AKIAABCDEFGHIJKLMNOP and 10.0.0.1");
        assert_eq!(highest_severity(&f), Severity::Critical);
    }
}
