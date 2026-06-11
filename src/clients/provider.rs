//! Shared PR models + the provider abstraction the reviewer talks to.
//!
//! The Python used a `Protocol`; here we use an `enum` for static dispatch
//! (no `async-trait`, no `dyn`). The reviewer holds a `Provider` and the enum
//! delegates each call to the concrete `BitbucketClient` / `GitHubClient`.
//! Provider-specific extras (GitHub thread replies, reviews, fix push) live on
//! `GitHubClient` directly and are reached by the interactive layer.

use serde::{Deserialize, Serialize};

use crate::clients::bitbucket::BitbucketClient;
use crate::clients::github::GitHubClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: u64,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub source_branch: String,
    pub destination_branch: String,
    /// HEAD of the PR branch — GitHub requires it (`commit_id`) on every inline
    /// review comment. Bitbucket ignores it on the wire.
    pub source_commit: String,
    pub destination_commit: String,
    pub author: String,
}

#[derive(Debug, Clone)]
pub struct InlineComment {
    pub file: String,
    pub line: u32,
    pub body: String,
    /// GitHub-only: head commit the comment anchors to.
    pub commit_id: Option<String>,
    /// Multi-line suggestion range start (GitHub). When set and `< line`, the
    /// client sends `start_line` + `start_side`.
    pub start_line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ExistingComment {
    pub id: i64,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub content: String,
    /// Login/display-name of the author — used for reply-to-bot detection.
    pub author: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Bitbucket,
    GitHub,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Bitbucket => "bitbucket",
            ProviderKind::GitHub => "github",
        }
    }
}

/// Static-dispatch wrapper over the concrete PR clients.
pub enum Provider {
    Bitbucket(BitbucketClient),
    GitHub(GitHubClient),
}

impl Provider {
    pub fn kind(&self) -> ProviderKind {
        match self {
            Provider::Bitbucket(_) => ProviderKind::Bitbucket,
            Provider::GitHub(_) => ProviderKind::GitHub,
        }
    }

    pub fn clone_host(&self) -> &str {
        match self {
            Provider::Bitbucket(c) => c.clone_host(),
            Provider::GitHub(c) => c.clone_host(),
        }
    }

    pub fn workspace(&self) -> &str {
        match self {
            Provider::Bitbucket(c) => c.workspace(),
            Provider::GitHub(c) => c.workspace(),
        }
    }

    pub fn repo_slug(&self) -> &str {
        match self {
            Provider::Bitbucket(c) => c.repo_slug(),
            Provider::GitHub(c) => c.repo_slug(),
        }
    }

    /// Username for the git-over-HTTPS clone URL.
    pub fn clone_username(&self) -> &str {
        match self {
            Provider::Bitbucket(c) => c.clone_username(),
            Provider::GitHub(c) => c.clone_username(),
        }
    }

    /// Token/password for the git-over-HTTPS clone URL.
    pub fn clone_token(&self) -> &str {
        match self {
            Provider::Bitbucket(c) => c.clone_token(),
            Provider::GitHub(c) => c.clone_token(),
        }
    }

    pub async fn get_pull_request(&self, pr_id: u64) -> anyhow::Result<PullRequest> {
        match self {
            Provider::Bitbucket(c) => Ok(c.get_pull_request(pr_id).await?),
            Provider::GitHub(c) => Ok(c.get_pull_request(pr_id).await?),
        }
    }

    pub async fn get_pull_request_diff(&self, pr_id: u64) -> anyhow::Result<String> {
        match self {
            Provider::Bitbucket(c) => Ok(c.get_pull_request_diff(pr_id).await?),
            Provider::GitHub(c) => Ok(c.get_pull_request_diff(pr_id).await?),
        }
    }

    pub async fn list_comments(&self, pr_id: u64) -> anyhow::Result<Vec<ExistingComment>> {
        match self {
            Provider::Bitbucket(c) => Ok(c.list_comments(pr_id).await?),
            Provider::GitHub(c) => Ok(c.list_comments(pr_id).await?),
        }
    }

    pub async fn post_summary_comment(&self, pr_id: u64, body: &str) -> anyhow::Result<()> {
        match self {
            Provider::Bitbucket(c) => c.post_summary_comment(pr_id, body).await?,
            Provider::GitHub(c) => c.post_summary_comment(pr_id, body).await?,
        };
        Ok(())
    }

    pub async fn post_inline_comment(&self, pr_id: u64, c: &InlineComment) -> anyhow::Result<()> {
        match self {
            Provider::Bitbucket(bb) => bb.post_inline_comment(pr_id, c).await?,
            Provider::GitHub(gh) => gh.post_inline_comment(pr_id, c).await?,
        };
        Ok(())
    }
}
