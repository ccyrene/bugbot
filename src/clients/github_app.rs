//! GitHub App authentication: mint short-lived **installation access tokens**
//! from the App's private key, so bugbot can act as its own `<slug>[bot]`
//! identity instead of a static Personal Access Token (PAT).
//!
//! Flow (per <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app>):
//!   1. Sign a short-lived **RS256 JWT** with the App private key (`iss = app_id`).
//!   2. `POST /app/installations/{id}/access_tokens` with that JWT → a token
//!      valid ~1h, scoped to the installation's repos.
//!   3. Use that installation token exactly like a PAT (REST + `x-access-token`
//!      git clone password).
//!
//! Installation tokens are **cached per installation** and refreshed well
//! before expiry — see [`TOKEN_USABLE_SECS`]. We keep `reqwest` (already a dep)
//! for HTTP rather than pulling in `octocrab`, matching the minimal-deps stance
//! of the rest of `clients/`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::clients::github::GitHubClient;
use crate::config::Settings;
use crate::libs::redact::redact;

/// How long we treat a freshly minted installation token as usable before
/// re-minting. GitHub installation tokens live **60 minutes**; capping reuse at
/// 40 leaves ≥20 min of real headroom — comfortably longer than any single
/// review/fix job (bounded by the codex/claude timeouts, ~15 min) — so a token
/// handed to an in-flight job never expires mid-run, while still avoiding a
/// per-request mint storm across many webhooks.
const TOKEN_USABLE_SECS: i64 = 2400;

/// JWT lifetime. GitHub rejects App JWTs whose lifetime exceeds 10 minutes; we
/// back-date `iat` 60s for clock skew and expire at +8 min (540s total span,
/// safely under the cap).
const JWT_IAT_BACKDATE_SECS: i64 = 60;
const JWT_EXP_SECS: i64 = 480;

const ACCEPT_JSON: &str = "application/vnd.github+json";

#[derive(Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

struct CachedToken {
    token: String,
    /// Epoch seconds after which we re-mint (well before real expiry).
    good_until: i64,
}

/// Mints + caches GitHub App installation tokens. Build once and share
/// (`Arc`) across the worker, mirroring the shared `FixLimiter`.
pub struct AppAuth {
    app_id: String,
    key: EncodingKey,
    http: Client,
    base_url: String,
    cache: Mutex<HashMap<u64, CachedToken>>,
}

impl AppAuth {
    /// Build from settings, returning `None` when the App is not configured
    /// (so callers transparently fall back to PAT auth) and `Err` when it is
    /// configured but the private key is unreadable/invalid (fail fast at
    /// startup rather than on the first webhook).
    pub fn from_settings(s: &Settings) -> anyhow::Result<Option<Arc<AppAuth>>> {
        if !s.github_app_enabled() {
            return Ok(None);
        }
        let app_id = s
            .github_app_id
            .clone()
            .expect("github_app_enabled implies app_id is set");
        let pem = load_private_key_pem(s)?;
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).context(
            "GitHub App private key is not a valid RSA PEM \
             (BUGBOT_GITHUB_APP_PRIVATE_KEY / _PATH)",
        )?;

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_JSON));
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("bugbot/0.2"));
        let http = Client::builder()
            .timeout(Duration::from_secs_f64(s.github_timeout_seconds))
            .default_headers(headers)
            .build()
            .context("building GitHub App HTTP client")?;

        Ok(Some(Arc::new(AppAuth {
            app_id,
            key,
            http,
            base_url: s.github_base_url.trim_end_matches('/').to_string(),
            cache: Mutex::new(HashMap::new()),
        })))
    }

    /// A cached or freshly minted installation token for `installation_id`.
    pub async fn installation_token(&self, installation_id: u64) -> anyhow::Result<String> {
        let now = unix_now();
        {
            let cache = self.cache.lock().await;
            if let Some(c) = cache.get(&installation_id) {
                if c.good_until > now {
                    return Ok(c.token.clone());
                }
            }
        }
        // Cache miss / stale: mint without holding the lock across the network
        // call. A benign race (two concurrent misses both mint) is fine — both
        // tokens are valid and last-write-wins, mirroring `FixLimiter`.
        let token = self.mint_installation_token(installation_id).await?;
        {
            let mut cache = self.cache.lock().await;
            cache.insert(
                installation_id,
                CachedToken {
                    token: token.clone(),
                    good_until: now + TOKEN_USABLE_SECS,
                },
            );
        }
        Ok(token)
    }

    /// Resolve the installation id that covers `owner/repo` (fallback for the
    /// CLI / a webhook that omitted `installation.id`).
    pub async fn installation_id_for_repo(&self, owner: &str, repo: &str) -> anyhow::Result<u64> {
        let jwt = self.app_jwt()?;
        let url = format!("{}/repos/{}/{}/installation", self.base_url, owner, repo);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&jwt)
            .send()
            .await
            .context("requesting repo installation")?;
        let status = resp.status();
        if !status.is_success() {
            let body = err_body(resp).await;
            anyhow::bail!(
                "repo installation lookup failed ({}): {body} — is the App installed on {}/{}?",
                status.as_u16(),
                owner,
                repo
            );
        }
        let v: Value = resp.json().await.context("parsing installation response")?;
        v.get("id")
            .and_then(Value::as_u64)
            .context("installation response missing numeric 'id'")
    }

    async fn mint_installation_token(&self, installation_id: u64) -> anyhow::Result<String> {
        let jwt = self.app_jwt()?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.base_url, installation_id
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .send()
            .await
            .context("requesting installation access token")?;
        let status = resp.status();
        if !status.is_success() {
            let body = err_body(resp).await;
            anyhow::bail!(
                "installation token request failed ({}): {body}",
                status.as_u16()
            );
        }
        let v: Value = resp
            .json()
            .await
            .context("parsing installation token response")?;
        v.get("token")
            .and_then(Value::as_str)
            .map(String::from)
            .context("installation token response missing 'token'")
    }

    /// Sign the App-level JWT used to call `/app/*` endpoints.
    fn app_jwt(&self) -> anyhow::Result<String> {
        let now = unix_now();
        let claims = AppJwtClaims {
            iat: now - JWT_IAT_BACKDATE_SECS,
            exp: now + JWT_EXP_SECS,
            iss: self.app_id.clone(),
        };
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.key)
            .context("signing GitHub App JWT")
    }
}

/// Build a `GitHubClient` for `owner/repo`, choosing installation-token auth
/// when the App is configured and falling back to the static PAT otherwise.
/// `installation_id` is the webhook hint; when absent (e.g. the `review-pr`
/// CLI) it is resolved from the repo.
pub async fn build_github_client(
    s: &Settings,
    app_auth: Option<&AppAuth>,
    owner: &str,
    repo: &str,
    installation_id: Option<u64>,
) -> anyhow::Result<GitHubClient> {
    if let Some(app) = app_auth {
        let inst = match installation_id {
            Some(id) => id,
            None => app
                .installation_id_for_repo(owner, repo)
                .await
                .with_context(|| format!("resolving installation id for {owner}/{repo}"))?,
        };
        let token = app
            .installation_token(inst)
            .await
            .with_context(|| format!("minting installation token for installation {inst}"))?;
        Ok(GitHubClient::new(
            &token,
            owner,
            repo,
            &s.github_base_url,
            s.github_timeout_seconds,
        )?)
    } else {
        let tok = s.github_token.as_ref().context(
            "GitHub not configured: set BUGBOT_GITHUB_TOKEN or the GitHub App credentials \
             (BUGBOT_GITHUB_APP_ID + BUGBOT_GITHUB_APP_PRIVATE_KEY / _PATH)",
        )?;
        Ok(GitHubClient::new(
            tok.expose(),
            owner,
            repo,
            &s.github_base_url,
            s.github_timeout_seconds,
        )?)
    }
}

fn load_private_key_pem(s: &Settings) -> anyhow::Result<String> {
    if let Some(path) = &s.github_app_private_key_path {
        return std::fs::read_to_string(path)
            .with_context(|| format!("reading GitHub App private key from {path}"));
    }
    let raw = s
        .github_app_private_key
        .as_ref()
        .context("github_app_enabled but no inline key (unreachable)")?
        .expose();
    // Env vars frequently store the PEM with literal `\n` rather than real
    // newlines; normalise so the PEM parser accepts it.
    Ok(if raw.contains("\\n") {
        raw.replace("\\n", "\n")
    } else {
        raw.to_string()
    })
}

async fn err_body(resp: reqwest::Response) -> String {
    let body = resp.text().await.unwrap_or_default();
    redact(&body).chars().take(300).collect()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde::Deserialize;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Throwaway RSA keypair (2048-bit) generated for tests only — never used
    // against real GitHub.
    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCREwjgdaP+tlpI\n\
0oej6E2dcX2op3euBtFJf6ZRBkjl+SOohQzi7pQrR6zsZw+VqQ4xoUa3LGRgsHPn\n\
wctALfLShid9B/a6Y/hj+Gk24bxKh6kLat3gffeEzKdJcoN0QrOimIByPkbWIKnu\n\
pE8j3KPRQIKWFsf/6d+JGPOie+sIrzAb+bBEquVxGHJUJXZb5rI1QJTOgy2tm0uZ\n\
mJJdwq92Q7XqHGItbtsz80qwaC1o7ODTxH4d4LomfRO3DogOyyoM0R5JZ6Ainb00\n\
kwA2WIIX/eIzFuQSG3Ko7BWdUFatq54cFAQZwyZXjtwT0eiddyXYXOkKo239qv2n\n\
brVWRXeHAgMBAAECggEAJa1QXl8fHs1EKGqI8LApzCyH6o/HvMone5Or4Zokv5lT\n\
QfaAEMXOdGkSh3kCqqczuP7+Kx9b2GKrT3Lcswfb6wINamLxmJnTDj+bL7YznRWb\n\
eQwhoKaGbJZsEd6sNjsGhUFfBoyXABCOoZxJs3Ifl35OC+XRvmyCcgwpZjcRpPja\n\
gv5TxB0yHEXRzifG1+mB0G6r43gZFiPJFX1dfJLWBP/fN2ojQzO6cPjVAVDan7eO\n\
si59rvV6YIoN4RWc19mJtaUWAyWPnI6jpjPreT+oGeYpqNOlbTaCV6zEQ4PN84w3\n\
ZAc6uU5B6tCpDExBT0GE3mfYrv7fN5L4q4G1wMZJlQKBgQDEVvoNKEm3YRbMtryI\n\
6aLiB9n6PC0JPQS1SdLzDiS6yZm7F9RBsLsbzVacjav5vnLuASPgVfEjqeY8jcw9\n\
lS3mrHYrvEU02XFrW497NC5p/lvzuebidIKpWxTGSJPoZOfdGT0aRiQ16h3KsooX\n\
e5LsLl/8GbkFeYK+RKPm/yYHBQKBgQC9KC/S1+ZiZ5MJW4m3W3FiEL2xKwt26W1R\n\
1bHrW43xjGkuZi3TWnZP03UWASLqYvpMrgP8EmKGEcs6eQUTj+QvyHwpltWnsemm\n\
Fd/18kl6khblAWQxlR1mNKs4EujS6oot21scFaZV+T5iAZg690yCCnpwUPrMpoHf\n\
Er1uUiDyGwKBgB62rG8aek2hdnuXqm6QfdZ1+/dVKoZjcTUa01EKSVye5NmLpLyR\n\
9PMocAAVeW2cCUaKDx6s0wgNL+MRG34WtBN9rw6waPMXgNKWhB91zjzueVvrHN8X\n\
8sijYuCRwfF8t3iy1ggiKM/2S6rFuyxpPFaN+p3pODRPCdDR1AHyr/QxAoGBAKWL\n\
Yi9YnFxK4TgzUJeUA+sbU6iWT3ZGXFJef1PH0LYxeGwPKNPsO9co7TPQ0snmzcAG\n\
G56kSG2lbQNDntm7+KyI/YE4bMxSvHWKd3M8FGqdKERLr3BlXFFyjtaIVhMhCMWR\n\
UG+H0wczFxGW66/Pdrnoibd6Z8RrhQXB1N+UKRk5AoGAOfTIsyXj98cT+LQMungh\n\
dy35x+kHkcztU+D/mvIu3Lg/P9lTJbNQYL7JIBXTAWoCTH+5GXa2xDz1SZ7Czm8l\n\
Wlof9ZmSCGaX/6SIe7jgmrLZzJOKu6vqGEJ7NWBG3Ii9Es6Ib0ToSZMzvbehW3Uk\n\
LhmWQ9jCdu3n8Ymh3x3jI5w=\n\
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkRMI4HWj/rZaSNKHo+hN\n\
nXF9qKd3rgbRSX+mUQZI5fkjqIUM4u6UK0es7GcPlakOMaFGtyxkYLBz58HLQC3y\n\
0oYnfQf2umP4Y/hpNuG8SoepC2rd4H33hMynSXKDdEKzopiAcj5G1iCp7qRPI9yj\n\
0UCClhbH/+nfiRjzonvrCK8wG/mwRKrlcRhyVCV2W+ayNUCUzoMtrZtLmZiSXcKv\n\
dkO16hxiLW7bM/NKsGgtaOzg08R+HeC6Jn0Ttw6IDssqDNEeSWegIp29NJMANliC\n\
F/3iMxbkEhtyqOwVnVBWraueHBQEGcMmV47cE9HonXcl2FzpCqNt/ar9p261VkV3\n\
hwIDAQAB\n\
-----END PUBLIC KEY-----";

    fn test_auth(base_url: &str) -> AppAuth {
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes())
            .expect("test private key parses");
        AppAuth {
            app_id: "123456".into(),
            key,
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[derive(Deserialize)]
    struct DecodedClaims {
        iss: String,
        iat: i64,
        exp: i64,
    }

    #[test]
    fn app_jwt_is_valid_rs256_with_expected_claims() {
        let auth = test_auth("https://api.github.com");
        let token = auth.app_jwt().expect("sign jwt");

        let header = jsonwebtoken::decode_header(&token).expect("decode header");
        assert_eq!(header.alg, Algorithm::RS256);

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        // We don't set audience; disable that check.
        validation.set_required_spec_claims(&["exp"]);
        let decoded = decode::<DecodedClaims>(
            &token,
            &DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY.as_bytes()).expect("pub key"),
            &validation,
        )
        .expect("jwt verifies against the public key");

        assert_eq!(decoded.claims.iss, "123456");
        assert!(decoded.claims.exp > decoded.claims.iat);
        // span = backdate + exp window
        assert_eq!(
            decoded.claims.exp - decoded.claims.iat,
            JWT_IAT_BACKDATE_SECS + JWT_EXP_SECS
        );
        // Within GitHub's 10-minute cap.
        assert!(decoded.claims.exp - decoded.claims.iat <= 600);
    }

    #[tokio::test]
    async fn installation_token_mints_then_serves_from_cache() {
        let server = MockServer::start().await;
        // Expect EXACTLY one mint despite two calls → proves caching.
        Mock::given(method("POST"))
            .and(path("/app/installations/42/access_tokens"))
            .and(header_exists("authorization")) // bearer JWT present
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_minted_token",
                "expires_at": "2999-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let auth = test_auth(&server.uri());
        let t1 = auth.installation_token(42).await.expect("mint");
        let t2 = auth.installation_token(42).await.expect("cache hit");
        assert_eq!(t1, "ghs_minted_token");
        assert_eq!(t2, "ghs_minted_token");
        // `.expect(1)` is verified on server drop.
    }

    #[tokio::test]
    async fn installation_id_for_repo_reads_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/widget/installation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": 987, "app_id": 123456 })),
            )
            .mount(&server)
            .await;

        let auth = test_auth(&server.uri());
        let id = auth
            .installation_id_for_repo("octo", "widget")
            .await
            .expect("resolve id");
        assert_eq!(id, 987);
    }

    #[tokio::test]
    async fn mint_surfaces_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/7/access_tokens"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&server)
            .await;

        let auth = test_auth(&server.uri());
        let err = auth.installation_token(7).await.unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
    }
}
