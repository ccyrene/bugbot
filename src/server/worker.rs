//! Bounded background job runner. Webhook handlers enqueue and return 202;
//! a `Semaphore` caps concurrency and a dedupe set drops same-job re-fires
//! (per provider/repo/PR, and per comment id for interactive jobs).
//! Ported + extended from `server/worker.py`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::clients::bitbucket::BitbucketClient;
use crate::clients::github_app::{self, AppAuth};
use crate::clients::llm::LlmBackend;
use crate::clients::provider::{Provider, ProviderKind};
use crate::config::Settings;
use crate::interactive::{self, FixLimiter};
use crate::review::Reviewer;
use crate::server::webhook_github::GithubComment;

#[derive(Debug, Clone)]
pub struct ReviewJob {
    pub provider: ProviderKind,
    pub workspace: String,
    pub repo_slug: String,
    pub pr_id: u64,
    pub domain: String,
    /// GitHub App installation id (GitHub jobs only); `None` under PAT auth.
    pub installation_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum Job {
    Review(ReviewJob),
    Interact(GithubComment),
}

impl Job {
    fn key(&self) -> String {
        match self {
            Job::Review(r) => format!(
                "review:{}:{}:{}:{}",
                r.provider.as_str(),
                r.workspace,
                r.repo_slug,
                r.pr_id
            ),
            Job::Interact(c) => format!(
                "interact:{}:{}:{}:{}",
                c.workspace, c.repo_slug, c.pr_id, c.comment_id
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("{0}")]
    Config(String),
}

/// Removes the dedupe key on drop — so a panicking task can't wedge the PR.
struct InflightGuard {
    set: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.lock() {
            s.remove(&self.key);
        }
    }
}

pub struct Worker {
    settings: Arc<Settings>,
    sem: Arc<Semaphore>,
    inflight: Arc<Mutex<HashSet<String>>>,
    fix_limiter: Arc<FixLimiter>,
    /// Present when the GitHub App is configured; `None` → static PAT auth.
    app_auth: Option<Arc<AppAuth>>,
}

impl Worker {
    /// Fallible because building the App auth validates the private key — a
    /// misconfigured App should fail at startup, not on the first webhook.
    pub fn new(settings: Arc<Settings>) -> anyhow::Result<Self> {
        let max = settings.max_concurrent_reviews.max(1);
        let fix_max = settings.fix_max_per_pr_24h;
        let app_auth = AppAuth::from_settings(&settings)?;
        Ok(Worker {
            settings,
            sem: Arc::new(Semaphore::new(max)),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            fix_limiter: Arc::new(FixLimiter::new(fix_max)),
            app_auth,
        })
    }

    /// Enqueue a job. Returns false if the same job is already in-flight.
    pub fn submit(&self, job: Job) -> bool {
        let key = job.key();
        {
            let mut set = self.inflight.lock().expect("inflight lock");
            if set.contains(&key) {
                tracing::info!("dedupe: job already in-flight {key}");
                return false;
            }
            set.insert(key.clone());
        }

        let settings = Arc::clone(&self.settings);
        let sem = Arc::clone(&self.sem);
        let inflight = Arc::clone(&self.inflight);
        let fix_limiter = Arc::clone(&self.fix_limiter);
        let app_auth = self.app_auth.clone();

        tokio::spawn(async move {
            let _guard = InflightGuard {
                set: inflight,
                key: key.clone(),
            };
            let _permit = sem.acquire_owned().await; // bound concurrency
            if let Err(e) = run_job(&settings, &fix_limiter, app_auth.as_deref(), job).await {
                tracing::error!("job {key} failed: {e:#}");
            }
        });
        true
    }
}

async fn run_job(
    settings: &Settings,
    fix_limiter: &FixLimiter,
    app_auth: Option<&AppAuth>,
    job: Job,
) -> anyhow::Result<()> {
    let llm = LlmBackend::from_settings(settings)?;
    match job {
        Job::Review(rj) => {
            tracing::info!(
                "starting review {}:{}/{}#{} (domain={})",
                rj.provider.as_str(),
                rj.workspace,
                rj.repo_slug,
                rj.pr_id,
                rj.domain
            );
            let provider = build_provider(settings, app_auth, &rj).await?;
            Reviewer::new(settings, &provider, &llm)
                .run(rj.pr_id, &rj.domain)
                .await?;
        }
        Job::Interact(comment) => {
            let gh = github_app::build_github_client(
                settings,
                app_auth,
                &comment.workspace,
                &comment.repo_slug,
                comment.installation_id,
            )
            .await?;
            interactive::handle_comment(settings, gh, &llm, &comment, fix_limiter).await?;
        }
    }
    Ok(())
}

async fn build_provider(
    s: &Settings,
    app_auth: Option<&AppAuth>,
    rj: &ReviewJob,
) -> Result<Provider, WorkerError> {
    match rj.provider {
        ProviderKind::Bitbucket => {
            let pw = s.bitbucket_app_password.as_ref().ok_or_else(|| {
                WorkerError::Config("Bitbucket job but BUGBOT_BITBUCKET_APP_PASSWORD unset".into())
            })?;
            let c = BitbucketClient::new(
                &s.bitbucket_username,
                pw.expose(),
                &rj.workspace,
                &rj.repo_slug,
                &s.bitbucket_base_url,
                s.bitbucket_timeout_seconds,
            )
            .map_err(|e| WorkerError::Config(e.to_string()))?;
            Ok(Provider::Bitbucket(c))
        }
        ProviderKind::GitHub => {
            let gh = github_app::build_github_client(
                s,
                app_auth,
                &rj.workspace,
                &rj.repo_slug,
                rj.installation_id,
            )
            .await
            .map_err(|e| WorkerError::Config(e.to_string()))?;
            Ok(Provider::GitHub(gh))
        }
    }
}
