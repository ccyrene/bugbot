//! End-to-end webhook server tests via `tower::ServiceExt::oneshot`. Covers
//! the auth + validation paths that do NOT enqueue real work (those would
//! spawn a clone + LLM run). Mirrors the Python `test_server_app` /
//! `test_webhook_auth` suites.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

use bugbot::config::{FixBranchStrategy, LlmBackendKind, Secret, Settings, Severity};
use bugbot::server::app::create_app;

const WH_SECRET: &str = "test-webhook-secret";

fn github_only_settings() -> Settings {
    Settings {
        llm_backend: LlmBackendKind::Codex,
        llm_fallback_backend: None,
        codex_cli_path: "codex".into(),
        codex_model: None,
        codex_reasoning_effort: None,
        codex_timeout_seconds: 900.0,
        claude_cli_path: "claude".into(),
        claude_model: "sonnet".into(),
        claude_effort: None,
        claude_timeout_seconds: 600.0,
        claude_allowed_tools: "Read,Grep,Glob".into(),
        bitbucket_username: "x-token-auth".into(),
        bitbucket_app_password: None, // bitbucket disabled
        bitbucket_base_url: "https://api.bitbucket.org/2.0".into(),
        bitbucket_timeout_seconds: 60.0,
        github_token: Some(Secret::new("ghtok")),
        github_app_id: None,
        github_app_private_key: None,
        github_app_private_key_path: None,
        github_webhook_secret: Some(Secret::new(WH_SECRET)),
        github_base_url: "https://api.github.com".into(),
        github_timeout_seconds: 60.0,
        github_webhook_path: "/webhook/github".into(),
        github_bot_login: Some("bugbot[bot]".into()),
        git_clone_depth: 50,
        git_clone_max_mb: 512,
        git_clone_timeout_seconds: 180.0,
        server_host: "127.0.0.1".into(),
        server_port: 8080,
        webhook_path: "/webhook/bitbucket".into(),
        webhook_secret: None,
        webhook_enforce_ip_allowlist: false, // no network in tests
        webhook_ip_cache_seconds: 3600,
        trust_forwarded_for: false,
        max_concurrent_reviews: 2,
        fail_on_severity: Severity::Critical,
        max_inline_comments: 20,
        max_diff_chars: 120_000,
        max_file_chars: 200_000,
        ignore_globs: String::new(),
        dry_run: false,
        bot_marker: "bugbot:v1".into(),
        default_domain: "general".into(),
        interactive_enabled: true,
        fix_enabled: true,
        fix_max_per_pr_24h: 3,
        fix_branch_strategy: FixBranchStrategy::NewBranch,
        log_level: "INFO".into(),
    }
}

fn sign(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(WH_SECRET.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

async fn send(mut req: Request<Body>) -> StatusCode {
    // Prod inserts ConnectInfo via into_make_service_with_connect_info; for
    // oneshot we inject it manually so the ConnectInfo extractor resolves.
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let app = create_app(Arc::new(github_only_settings())).expect("create_app");
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn healthz_reports_providers() {
    let app = create_app(Arc::new(github_only_settings())).expect("create_app");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["providers"]["github"], true);
    assert_eq!(v["providers"]["bitbucket"], false);
}

#[tokio::test]
async fn github_bad_signature_is_401() {
    let body = b"{}";
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/github")
        .header("x-github-event", "pull_request")
        .header("x-hub-signature-256", "sha256=deadbeef")
        .body(Body::from(body.to_vec()))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn github_missing_signature_is_401() {
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/github")
        .header("x-github-event", "pull_request")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn github_ping_with_valid_signature_is_204() {
    let body = br#"{"zen":"hi"}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/github")
        .header("x-github-event", "ping")
        .header("x-hub-signature-256", sign(body))
        .body(Body::from(body.to_vec()))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn github_unknown_domain_is_400() {
    // Valid signature + a real PR body, but a bogus domain segment → 400
    // (domain validated after auth, before enqueue).
    let body = br#"{"action":"opened","repository":{"full_name":"o/r"},"pull_request":{"number":1,"draft":false},"sender":{"login":"x"}}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/github/not-a-real-domain")
        .header("x-github-event", "pull_request")
        .header("x-hub-signature-256", sign(body))
        .body(Body::from(body.to_vec()))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bitbucket_not_configured_is_503() {
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/bitbucket")
        .header("x-event-key", "pullrequest:created")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn github_non_trigger_action_is_204() {
    // 'labeled' is recognised but not a trigger and has no comment → Ignore → 204.
    let body = br#"{"action":"labeled","repository":{"full_name":"o/r"},"pull_request":{"number":1},"sender":{"login":"x"}}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/webhook/github")
        .header("x-github-event", "pull_request")
        .header("x-hub-signature-256", sign(body))
        .body(Body::from(body.to_vec()))
        .unwrap();
    assert_eq!(send(req).await, StatusCode::NO_CONTENT);
}
