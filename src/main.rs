//! bugbot CLI. Subcommands: `serve`, `review-pr`, `scan`, `version`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use bugbot::clients::bitbucket::BitbucketClient;
use bugbot::clients::github_app::{self, AppAuth};
use bugbot::clients::llm::LlmBackend;
use bugbot::clients::provider::Provider;
use bugbot::config::{Settings, Severity};
use bugbot::libs::logging;
use bugbot::review::{result_to_json, Reviewer};
use bugbot::server::app::create_app;
use bugbot::services::diff::parse_unified_diff;
use bugbot::services::security::scan_diff;

#[derive(Parser)]
#[command(
    name = "bugbot",
    version,
    about = "Bitbucket/GitHub AI PR reviewer (codex/claude backed)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the FastAPI-equivalent webhook server.
    Serve {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Run a one-off review against a specific PR (debug / manual re-review).
    #[command(name = "review-pr")]
    ReviewPr {
        /// Workspace (Bitbucket) or owner (GitHub).
        workspace: String,
        /// Repository slug.
        repo_slug: String,
        /// Pull request id.
        pr_id: u64,
        #[arg(long, short = 'P', default_value = "bitbucket")]
        provider: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        artifact: Option<PathBuf>,
    },
    /// Run the secret scanner against a local diff file (no network).
    Scan {
        diff_path: PathBuf,
        #[arg(long, default_value = "high")]
        fail_on: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print the version.
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Scan {
            diff_path,
            fail_on,
            output,
        } => cmd_scan(diff_path, &fail_on, output),
        Cmd::Serve { host, port } => cmd_serve(host, port).await,
        Cmd::ReviewPr {
            workspace,
            repo_slug,
            pr_id,
            provider,
            domain,
            artifact,
        } => cmd_review_pr(workspace, repo_slug, pr_id, provider, domain, artifact).await,
    }
}

async fn cmd_serve(host: Option<String>, port: Option<u16>) -> Result<()> {
    let settings = Settings::load().context("loading settings")?;
    logging::init(&settings.log_level);
    let host = host.unwrap_or_else(|| settings.server_host.clone());
    let port = port.unwrap_or(settings.server_port);

    tracing::info!(
        "bugbot serve — backend={:?} bitbucket={} github={} interactive={} on {host}:{port}",
        settings.llm_backend,
        settings.bitbucket_enabled(),
        settings.github_enabled(),
        settings.interactive_enabled,
    );

    let app = create_app(Arc::new(settings))?;
    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .with_context(|| format!("binding {host}:{port}"))?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
    tracing::info!("shutdown signal received");
}

async fn cmd_review_pr(
    workspace: String,
    repo_slug: String,
    pr_id: u64,
    provider: String,
    domain: Option<String>,
    artifact: Option<PathBuf>,
) -> Result<()> {
    let settings = Settings::load().context("loading settings")?;
    logging::init(&settings.log_level);
    let provider_norm = provider.trim().to_lowercase();

    let prov = match provider_norm.as_str() {
        "bitbucket" => {
            let pw = settings.bitbucket_app_password.as_ref().context(
                "Bitbucket not configured — set BUGBOT_BITBUCKET_APP_PASSWORD/BITBUCKET_TOKEN",
            )?;
            Provider::Bitbucket(BitbucketClient::new(
                &settings.bitbucket_username,
                pw.expose(),
                &workspace,
                &repo_slug,
                &settings.bitbucket_base_url,
                settings.bitbucket_timeout_seconds,
            )?)
        }
        "github" => {
            // App auth when configured (resolves the installation from the
            // repo, since there's no webhook to carry it), else static PAT.
            let app_auth = AppAuth::from_settings(&settings)?;
            let gh = github_app::build_github_client(
                &settings,
                app_auth.as_deref(),
                &workspace,
                &repo_slug,
                None,
            )
            .await?;
            Provider::GitHub(gh)
        }
        other => anyhow::bail!("--provider must be 'bitbucket' or 'github', got {other:?}"),
    };

    let llm = LlmBackend::from_settings(&settings)?;
    let domain = domain.unwrap_or_else(|| settings.default_domain.clone());
    tracing::info!(
        "manual review: {provider_norm}:{workspace}/{repo_slug}#{pr_id} (domain={domain})"
    );

    let result = Reviewer::new(&settings, &prov, &llm)
        .run(pr_id, &domain)
        .await?;
    let payload = result_to_json(&result);
    if let Some(path) = artifact {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &payload)
            .with_context(|| format!("writing artifact {}", path.display()))?;
        tracing::info!("wrote review artefact -> {}", path.display());
    }
    Ok(())
}

fn cmd_scan(diff_path: PathBuf, fail_on: &str, output: Option<PathBuf>) -> Result<()> {
    logging::init("INFO");
    let text = std::fs::read_to_string(&diff_path)
        .with_context(|| format!("reading {}", diff_path.display()))?;
    let files = parse_unified_diff(&text);
    let findings = scan_diff(&files);

    let payload = json!({
        "findings": findings.iter().map(|f| json!({
            "file": f.file,
            "line": f.line,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity.as_str(),
            "snippet": f.snippet,
        })).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&payload)?;
    if let Some(path) = &output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, &text)?;
    }
    println!("{text}");

    let fail_on = Severity::parse(fail_on).unwrap_or(Severity::High);
    let top = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::None);
    if fail_on != Severity::None && top.rank() >= fail_on.rank() {
        tracing::error!(
            "secret scanner failed: top severity '{}' >= '{}'",
            top.as_str(),
            fail_on.as_str()
        );
        std::process::exit(2);
    }
    Ok(())
}
