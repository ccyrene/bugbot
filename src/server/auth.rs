//! Webhook auth: HMAC-SHA256 signature verify + per-provider IP allowlists.
//! Ported from `server/auth.py`.

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use ipnet::IpNet;
use reqwest::Client;
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

const ATLASSIAN_IP_URL: &str = "https://ip-ranges.atlassian.com/";
const GITHUB_META_URL: &str = "https://api.github.com/meta";

/// Constant-time HMAC-SHA256 check against a `sha256=<hex>` header. Works for
/// both Bitbucket (`X-Hub-Signature`) and GitHub (`X-Hub-Signature-256`).
pub fn verify_hmac_signature(body: &[u8], header: Option<&str>, secret: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Resolve the client IP, honouring `X-Forwarded-For` only behind a trusted proxy.
pub fn client_ip(peer: &str, forwarded_for: Option<&str>, trust_forwarded: bool) -> String {
    if trust_forwarded {
        if let Some(xff) = forwarded_for {
            if let Some(first) = xff.split(',').next() {
                let first = first.trim();
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    peer.to_string()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AllowlistKind {
    Bitbucket,
    GitHub,
}

struct CacheEntry {
    networks: Vec<IpNet>,
    fetched_at: Instant,
}

pub struct IpAllowlist {
    kind: AllowlistKind,
    name: &'static str,
    url: &'static str,
    refresh: Duration,
    timeout: Duration,
    client: Client,
    cache: Mutex<Option<CacheEntry>>,
}

impl IpAllowlist {
    pub fn new(kind: AllowlistKind, refresh_seconds: u64) -> Self {
        let (name, url) = match kind {
            AllowlistKind::Bitbucket => ("Atlassian IP allowlist", ATLASSIAN_IP_URL),
            AllowlistKind::GitHub => ("GitHub IP allowlist", GITHUB_META_URL),
        };
        IpAllowlist {
            kind,
            name,
            url,
            refresh: Duration::from_secs(refresh_seconds),
            timeout: Duration::from_secs(10),
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("bugbot/0.2")
                .build()
                .expect("allowlist http client"),
            cache: Mutex::new(None),
        }
    }

    fn parse_cidrs(&self, data: &Value) -> Vec<IpNet> {
        let raw: Vec<String> = match self.kind {
            AllowlistKind::Bitbucket => data
                .get("items")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.get("cidr").and_then(Value::as_str).map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            // GitHub /meta `hooks` is a flat array of CIDR strings.
            AllowlistKind::GitHub => data
                .get("hooks")
                .and_then(Value::as_array)
                .map(|h| {
                    h.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        };
        raw.iter().filter_map(|c| c.parse::<IpNet>().ok()).collect()
    }

    async fn fetch(&self) -> anyhow::Result<Vec<IpNet>> {
        let _ = self.timeout; // timeout baked into the client
        let resp = self.client.get(self.url).send().await?.error_for_status()?;
        let data: Value = resp.json().await?;
        let nets = self.parse_cidrs(&data);
        if nets.is_empty() {
            anyhow::bail!("{} feed returned no usable CIDRs", self.name);
        }
        Ok(nets)
    }

    /// True if `ip` is in the allowlist. Fail-open on the FIRST fetch failure
    /// (don't brick on a network blip); fail-closed thereafter against the
    /// last known list.
    pub async fn is_allowed(&self, ip: &str) -> bool {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        let mut guard = self.cache.lock().await;
        let now = Instant::now();
        let stale = guard
            .as_ref()
            .is_none_or(|c| now.duration_since(c.fetched_at) >= self.refresh);
        if stale {
            match self.fetch().await {
                Ok(nets) => {
                    tracing::info!("refreshed {} ({} CIDRs)", self.name, nets.len());
                    *guard = Some(CacheEntry {
                        networks: nets,
                        fetched_at: now,
                    });
                }
                Err(e) => {
                    tracing::warn!("could not refresh {}: {e}", self.name);
                    if guard.is_none() {
                        tracing::warn!(
                            "{} unavailable — admitting {} (first-run fail-open)",
                            self.name,
                            ip
                        );
                        return true;
                    }
                    // else: keep the stale cache and check against it.
                }
            }
        }
        match guard.as_ref() {
            Some(c) => c.networks.iter().any(|n| n.contains(&addr)),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() {
        // Known vector from GitHub docs.
        let secret = "It's a Secret to Everybody";
        let body = b"Hello, World!";
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            sig,
            "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        );
        assert!(verify_hmac_signature(
            body,
            Some(&format!("sha256={sig}")),
            secret
        ));
        assert!(!verify_hmac_signature(
            body,
            Some("sha256=deadbeef"),
            secret
        ));
        assert!(!verify_hmac_signature(body, None, secret));
        assert!(!verify_hmac_signature(body, Some("nope"), secret));
    }

    #[test]
    fn client_ip_honours_trust_flag() {
        assert_eq!(
            client_ip("1.2.3.4", Some("9.9.9.9, 1.1.1.1"), true),
            "9.9.9.9"
        );
        assert_eq!(client_ip("1.2.3.4", Some("9.9.9.9"), false), "1.2.3.4");
        assert_eq!(client_ip("1.2.3.4", None, true), "1.2.3.4");
    }

    #[test]
    fn parse_github_and_bitbucket_cidrs() {
        let gh = IpAllowlist::new(AllowlistKind::GitHub, 3600);
        let nets = gh.parse_cidrs(&serde_json::json!({"hooks": ["192.30.252.0/22", "::1/128"]}));
        assert_eq!(nets.len(), 2);
        let bb = IpAllowlist::new(AllowlistKind::Bitbucket, 3600);
        let nets = bb.parse_cidrs(&serde_json::json!({"items": [{"cidr": "13.52.5.0/25"}]}));
        assert_eq!(nets.len(), 1);
    }
}
