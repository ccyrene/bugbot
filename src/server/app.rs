//! axum app: healthcheck + Bitbucket/GitHub webhook endpoints (each with an
//! optional `/{domain}` focus suffix). Ported from `server/app.py`.
//!
//! Order per request: IP allowlist → HMAC over the RAW body → domain
//! validation → parse → enqueue → 202. HMAC is computed over the exact bytes,
//! so the body-consuming `Bytes` extractor must be LAST.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

use crate::clients::provider::ProviderKind;
use crate::config::Settings;
use crate::prompts::is_valid_domain;
use crate::server::auth::{client_ip, verify_hmac_signature, AllowlistKind, IpAllowlist};
use crate::server::webhook::parse_bitbucket;
use crate::server::webhook_github::{parse_github, GithubEvent};
use crate::server::worker::{Job, ReviewJob, Worker};

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub worker: Arc<Worker>,
    pub ip_bitbucket: Arc<IpAllowlist>,
    pub ip_github: Arc<IpAllowlist>,
}

pub fn create_app(settings: Arc<Settings>) -> Router {
    let state = AppState {
        worker: Arc::new(Worker::new(Arc::clone(&settings))),
        ip_bitbucket: Arc::new(IpAllowlist::new(
            AllowlistKind::Bitbucket,
            settings.webhook_ip_cache_seconds,
        )),
        ip_github: Arc::new(IpAllowlist::new(
            AllowlistKind::GitHub,
            settings.webhook_ip_cache_seconds,
        )),
        settings: Arc::clone(&settings),
    };

    let bb = settings.webhook_path.clone();
    let gh = settings.github_webhook_path.clone();

    Router::new()
        .route("/healthz", get(healthz))
        .route(&bb, post(bb_base))
        .route(&format!("{bb}/{{domain}}"), post(bb_domain))
        .route(&gh, post(gh_base))
        .route(&format!("{gh}/{{domain}}"), post(gh_domain))
        .with_state(state)
}

async fn healthz(State(st): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "providers": {
            "bitbucket": st.settings.bitbucket_enabled(),
            "github": st.settings.github_enabled(),
        }
    }))
}

fn header<'a>(h: &'a HeaderMap, key: &str) -> Option<&'a str> {
    h.get(key).and_then(|v| v.to_str().ok())
}

fn resolve_domain(raw: Option<&str>, default: &str) -> Result<String, (StatusCode, String)> {
    match raw {
        None | Some("") => Ok(default.to_string()),
        Some(d) if is_valid_domain(d) => Ok(d.to_string()),
        Some(d) => Err((
            StatusCode::BAD_REQUEST,
            format!("unknown review domain {d:?}"),
        )),
    }
}

/// Resolve the TCP peer IP from the `ConnectInfo` (inserted in prod by
/// `into_make_service_with_connect_info`; injected as an extension in tests).
fn peer_ip(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

// ---- Bitbucket ------------------------------------------------------------

async fn bb_base(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_bitbucket(st, None, peer_ip(addr), headers, body).await
}

async fn bb_domain(
    State(st): State<AppState>,
    Path(domain): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_bitbucket(st, Some(domain), peer_ip(addr), headers, body).await
}

async fn handle_bitbucket(
    st: AppState,
    domain: Option<String>,
    peer: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let s = &st.settings;
    if !s.bitbucket_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "bitbucket not configured").into_response();
    }
    let event_key = header(&headers, "x-event-key");

    if s.webhook_enforce_ip_allowlist {
        let src = client_ip(
            &peer,
            header(&headers, "x-forwarded-for"),
            s.trust_forwarded_for,
        );
        if !st.ip_bitbucket.is_allowed(&src).await {
            tracing::warn!("rejecting bitbucket webhook from non-Atlassian IP {src}");
            return (StatusCode::FORBIDDEN, "ip not allowed").into_response();
        }
    }

    let secret = s.webhook_secret.as_ref().expect("validated at startup");
    if !verify_hmac_signature(&body, header(&headers, "x-hub-signature"), secret.expose()) {
        tracing::warn!(
            "rejecting bitbucket webhook with bad/missing signature event={event_key:?}"
        );
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }

    let domain = match resolve_domain(domain.as_deref(), &s.default_domain) {
        Ok(d) => d,
        Err(resp) => return resp.into_response(),
    };

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "malformed JSON body").into_response(),
    };

    let event = match parse_bitbucket(event_key, &payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::info!("ignoring unparseable bitbucket webhook: {e}");
            return StatusCode::NO_CONTENT.into_response();
        }
    };
    if !event.is_trigger {
        tracing::info!("ignoring non-trigger bitbucket event {}", event.event_key);
        return StatusCode::NO_CONTENT.into_response();
    }

    let accepted = st.worker.submit(Job::Review(ReviewJob {
        provider: ProviderKind::Bitbucket,
        workspace: event.workspace.clone(),
        repo_slug: event.repo_slug.clone(),
        pr_id: event.pr_id,
        domain: domain.clone(),
    }));
    tracing::info!(
        "{} bitbucket review {}/{}#{} (event={}, actor={}, domain={})",
        if accepted { "accepted" } else { "deduped" },
        event.workspace,
        event.repo_slug,
        event.pr_id,
        event.event_key,
        event.actor,
        domain
    );
    accepted_json(accepted, event.pr_id, &domain)
}

// ---- GitHub ---------------------------------------------------------------

async fn gh_base(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_github(st, None, peer_ip(addr), headers, body).await
}

async fn gh_domain(
    State(st): State<AppState>,
    Path(domain): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_github(st, Some(domain), peer_ip(addr), headers, body).await
}

async fn handle_github(
    st: AppState,
    domain: Option<String>,
    peer: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let s = &st.settings;
    if !s.github_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "github not configured").into_response();
    }
    let event_header = header(&headers, "x-github-event");

    if s.webhook_enforce_ip_allowlist {
        let src = client_ip(
            &peer,
            header(&headers, "x-forwarded-for"),
            s.trust_forwarded_for,
        );
        if !st.ip_github.is_allowed(&src).await {
            tracing::warn!("rejecting github webhook from non-GitHub IP {src}");
            return (StatusCode::FORBIDDEN, "ip not allowed").into_response();
        }
    }

    let secret = s
        .github_webhook_secret
        .as_ref()
        .expect("validated at startup");
    if !verify_hmac_signature(
        &body,
        header(&headers, "x-hub-signature-256"),
        secret.expose(),
    ) {
        tracing::warn!(
            "rejecting github webhook with bad/missing signature event={event_header:?}"
        );
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }

    if event_header == Some("ping") {
        return StatusCode::NO_CONTENT.into_response();
    }

    let domain = match resolve_domain(domain.as_deref(), &s.default_domain) {
        Ok(d) => d,
        Err(resp) => return resp.into_response(),
    };

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "malformed JSON body").into_response(),
    };

    let event = match parse_github(event_header, &payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::info!("ignoring unparseable github webhook: {e}");
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    match event {
        GithubEvent::Ignore(reason) => {
            tracing::info!("ignoring github event ({reason})");
            StatusCode::NO_CONTENT.into_response()
        }
        GithubEvent::PrTrigger {
            workspace,
            repo_slug,
            pr_id,
            action,
            actor,
        } => {
            let accepted = st.worker.submit(Job::Review(ReviewJob {
                provider: ProviderKind::GitHub,
                workspace: workspace.clone(),
                repo_slug: repo_slug.clone(),
                pr_id,
                domain: domain.clone(),
            }));
            tracing::info!(
                "{} github review {}/{}#{} (action={}, actor={}, domain={})",
                if accepted { "accepted" } else { "deduped" },
                workspace,
                repo_slug,
                pr_id,
                action,
                actor,
                domain
            );
            accepted_json(accepted, pr_id, &domain)
        }
        GithubEvent::Comment(comment) => {
            if !s.interactive_enabled {
                tracing::info!(
                    "interactivity disabled — ignoring comment on #{}",
                    comment.pr_id
                );
                return StatusCode::NO_CONTENT.into_response();
            }
            let pr_id = comment.pr_id;
            let accepted = st.worker.submit(Job::Interact(comment));
            tracing::info!(
                "{} github interaction on #{}",
                if accepted { "accepted" } else { "deduped" },
                pr_id
            );
            accepted_json(accepted, pr_id, &domain)
        }
    }
}

fn accepted_json(accepted: bool, pr_id: u64, domain: &str) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": if accepted { "accepted" } else { "deduped" },
            "pr_id": pr_id,
            "domain": domain,
        })),
    )
        .into_response()
}
