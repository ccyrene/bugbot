//! Bitbucket Cloud v2 PR client. Ported from `clients/bitbucket.py`.
//! Bitbucket already works well in production; this keeps full parity.

use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::{json, Value};

use crate::clients::provider::{ExistingComment, InlineComment, PullRequest};
use crate::libs::redact::redact;

const TOKEN_AUTH_USERNAME: &str = "x-token-auth";
const CLONE_HOST: &str = "bitbucket.org";

#[derive(Debug, thiserror::Error)]
pub enum BitbucketError {
    #[error("bitbucket {action} failed ({status}): {body}")]
    Api {
        action: &'static str,
        status: u16,
        body: String,
    },
    #[error("bitbucket transport error: {0}")]
    Http(#[from] reqwest::Error),
}

enum Auth {
    Bearer(String),
    Basic { user: String, pass: String },
}

pub struct BitbucketClient {
    http: Client,
    base_url: String,
    workspace: String,
    repo_slug: String,
    username: String,
    token: String,
    auth: Auth,
}

impl BitbucketClient {
    pub fn new(
        username: &str,
        app_password: &str,
        workspace: &str,
        repo_slug: &str,
        base_url: &str,
        timeout_secs: f64,
    ) -> Result<Self, BitbucketError> {
        // Repository/Workspace Access Tokens need Bearer; App Passwords use
        // HTTP basic with the account email as username.
        let auth = if username == TOKEN_AUTH_USERNAME {
            Auth::Bearer(app_password.to_string())
        } else {
            Auth::Basic {
                user: username.to_string(),
                pass: app_password.to_string(),
            }
        };
        let http = Client::builder()
            .timeout(Duration::from_secs_f64(timeout_secs))
            .user_agent("bugbot/0.2")
            .build()?;
        Ok(BitbucketClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            workspace: workspace.to_string(),
            repo_slug: repo_slug.to_string(),
            username: username.to_string(),
            token: app_password.to_string(),
            auth,
        })
    }

    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    pub fn repo_slug(&self) -> &str {
        &self.repo_slug
    }
    pub fn clone_host(&self) -> &str {
        CLONE_HOST
    }
    pub fn clone_username(&self) -> &str {
        &self.username
    }
    pub fn clone_token(&self) -> &str {
        &self.token
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/repositories/{}/{}{}",
            self.base_url, self.workspace, self.repo_slug, suffix
        )
    }

    fn apply_auth(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Auth::Bearer(t) => rb.bearer_auth(t),
            Auth::Basic { user, pass } => rb.basic_auth(user, Some(pass)),
        }
    }

    async fn check(
        resp: reqwest::Response,
        action: &'static str,
    ) -> Result<reqwest::Response, BitbucketError> {
        let status = resp.status();
        if status.as_u16() >= 400 {
            let body = resp.text().await.unwrap_or_default();
            let body: String = redact(&body).chars().take(500).collect();
            return Err(BitbucketError::Api {
                action,
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp)
    }

    async fn get_json(&self, url: &str, action: &'static str) -> Result<Value, BitbucketError> {
        let resp = self.apply_auth(self.http.get(url)).send().await?;
        let resp = Self::check(resp, action).await?;
        Ok(resp.json::<Value>().await?)
    }

    /// Follow Bitbucket's `next` cursor, collecting every `values[]` entry.
    async fn paginate(
        &self,
        first_url: String,
        action: &'static str,
    ) -> Result<Vec<Value>, BitbucketError> {
        let mut out = Vec::new();
        let mut next = Some(first_url);
        while let Some(url) = next {
            let data = self.get_json(&url, action).await?;
            if let Some(values) = data.get("values").and_then(Value::as_array) {
                out.extend(values.iter().cloned());
            }
            next = data.get("next").and_then(Value::as_str).map(String::from);
        }
        Ok(out)
    }

    pub async fn get_pull_request(&self, pr_id: u64) -> Result<PullRequest, BitbucketError> {
        let data = self
            .get_json(
                &self.url(&format!("/pullrequests/{pr_id}")),
                "get_pull_request",
            )
            .await?;
        let s = |path: &[&str]| -> String {
            let mut cur = &data;
            for k in path {
                cur = match cur.get(k) {
                    Some(v) => v,
                    None => return String::new(),
                };
            }
            cur.as_str().unwrap_or_default().to_string()
        };
        Ok(PullRequest {
            id: data.get("id").and_then(Value::as_u64).unwrap_or(pr_id),
            title: s(&["title"]),
            description: s(&["description"]),
            source_branch: s(&["source", "branch", "name"]),
            destination_branch: s(&["destination", "branch", "name"]),
            source_commit: s(&["source", "commit", "hash"]),
            destination_commit: s(&["destination", "commit", "hash"]),
            author: {
                let a = s(&["author", "display_name"]);
                if a.is_empty() {
                    "unknown".to_string()
                } else {
                    a
                }
            },
        })
    }

    pub async fn get_pull_request_diff(&self, pr_id: u64) -> Result<String, BitbucketError> {
        // The diff endpoint 302s to a commit-keyed URL; reqwest follows
        // redirects by default.
        let resp = self
            .apply_auth(
                self.http
                    .get(self.url(&format!("/pullrequests/{pr_id}/diff"))),
            )
            .send()
            .await?;
        let resp = Self::check(resp, "get_pull_request_diff").await?;
        Ok(resp.text().await?)
    }

    pub async fn list_comments(&self, pr_id: u64) -> Result<Vec<ExistingComment>, BitbucketError> {
        let raw = self
            .paginate(
                self.url(&format!("/pullrequests/{pr_id}/comments")),
                "list_comments",
            )
            .await?;
        let mut out = Vec::new();
        for c in raw {
            if c.get("deleted").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            let inline = c.get("inline");
            let file = inline
                .and_then(|i| i.get("path"))
                .and_then(Value::as_str)
                .map(String::from);
            let line = inline
                .and_then(|i| {
                    i.get("to")
                        .and_then(Value::as_u64)
                        .or_else(|| i.get("from").and_then(Value::as_u64))
                })
                .map(|n| n as u32);
            out.push(ExistingComment {
                id: c.get("id").and_then(Value::as_i64).unwrap_or(0),
                file,
                line,
                content: c
                    .get("content")
                    .and_then(|x| x.get("raw"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                author: c
                    .get("user")
                    .and_then(|u| u.get("display_name"))
                    .and_then(Value::as_str)
                    .map(String::from),
            });
        }
        Ok(out)
    }

    pub async fn post_summary_comment(
        &self,
        pr_id: u64,
        body: &str,
    ) -> Result<Value, BitbucketError> {
        let payload = json!({ "content": { "raw": body } });
        let resp = self
            .apply_auth(
                self.http
                    .post(self.url(&format!("/pullrequests/{pr_id}/comments"))),
            )
            .json(&payload)
            .send()
            .await?;
        let resp = Self::check(resp, "post_summary_comment").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    pub async fn post_inline_comment(
        &self,
        pr_id: u64,
        comment: &InlineComment,
    ) -> Result<Value, BitbucketError> {
        // Bitbucket inline comment: `inline.to` = line in the new file.
        let payload = json!({
            "content": { "raw": comment.body },
            "inline": { "path": comment.file, "to": comment.line },
        });
        let resp = self
            .apply_auth(
                self.http
                    .post(self.url(&format!("/pullrequests/{pr_id}/comments"))),
            )
            .json(&payload)
            .send()
            .await?;
        let resp = Self::check(resp, "post_inline_comment").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }
}
