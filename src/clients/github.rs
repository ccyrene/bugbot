//! GitHub REST v3 PR client. Ports `clients/github.py` and adds the
//! interactive surface: authenticated identity, review-comment thread
//! fetching, in-thread replies, and PR creation for the fix flow.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::Client;
use serde_json::{json, Value};

use crate::clients::provider::{ExistingComment, InlineComment, PullRequest};
use crate::libs::redact::redact;

const CLONE_HOST: &str = "github.com";
const GIT_CLONE_USERNAME: &str = "x-access-token";
const ACCEPT_JSON: &str = "application/vnd.github+json";
const ACCEPT_DIFF: &str = "application/vnd.github.v3.diff";

static NEXT_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<([^>]+)>;\s*rel="next""#).expect("link re"));

#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    #[error("github {action} failed ({status}): {body}")]
    Api {
        action: &'static str,
        status: u16,
        body: String,
    },
    #[error("github transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("github: {0}")]
    Invalid(&'static str),
}

/// A review (inline) comment, structured for thread reconstruction.
#[derive(Debug, Clone)]
pub struct ReviewComment {
    pub id: i64,
    pub in_reply_to_id: Option<i64>,
    pub body: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub user: String,
    pub diff_hunk: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssueComment {
    pub id: i64,
    pub body: String,
    pub user: String,
}

pub struct GitHubClient {
    http: Client,
    base_url: String,
    owner: String,
    repo: String,
    token: String,
}

impl GitHubClient {
    pub fn new(
        token: &str,
        owner: &str,
        repo: &str,
        base_url: &str,
        timeout_secs: f64,
    ) -> Result<Self, GitHubError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| GitHubError::Invalid("token has invalid header bytes"))?,
        );
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("bugbot/0.2"));
        let http = Client::builder()
            .timeout(Duration::from_secs_f64(timeout_secs))
            .default_headers(headers)
            .build()?;
        Ok(GitHubClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            token: token.to_string(),
        })
    }

    pub fn workspace(&self) -> &str {
        &self.owner
    }
    pub fn repo_slug(&self) -> &str {
        &self.repo
    }
    pub fn clone_host(&self) -> &str {
        CLONE_HOST
    }
    pub fn clone_username(&self) -> &str {
        GIT_CLONE_USERNAME
    }
    pub fn clone_token(&self) -> &str {
        &self.token
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn repo(&self) -> &str {
        &self.repo
    }
    pub fn token(&self) -> &str {
        &self.token
    }

    fn repo_url(&self, suffix: &str) -> String {
        format!(
            "{}/repos/{}/{}{}",
            self.base_url, self.owner, self.repo, suffix
        )
    }

    async fn check(
        resp: reqwest::Response,
        action: &'static str,
    ) -> Result<reqwest::Response, GitHubError> {
        let status = resp.status();
        if status.as_u16() >= 400 {
            let body = resp.text().await.unwrap_or_default();
            let body: String = redact(&body).chars().take(500).collect();
            return Err(GitHubError::Api {
                action,
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp)
    }

    async fn get_json(&self, url: &str, action: &'static str) -> Result<Value, GitHubError> {
        let resp = self
            .http
            .get(url)
            .header(ACCEPT, ACCEPT_JSON)
            .send()
            .await?;
        let resp = Self::check(resp, action).await?;
        Ok(resp.json::<Value>().await?)
    }

    /// Follow GitHub's RFC-5988 `Link: …rel="next"` pagination, flattening
    /// every list page into one Vec.
    async fn paginate(
        &self,
        first: String,
        action: &'static str,
    ) -> Result<Vec<Value>, GitHubError> {
        let mut out = Vec::new();
        let mut next = Some(first);
        let mut first_hop = true;
        while let Some(url) = next.take() {
            let mut req = self.http.get(&url).header(ACCEPT, ACCEPT_JSON);
            if first_hop {
                req = req.query(&[("per_page", "100")]);
                first_hop = false;
            }
            let resp = Self::check(req.send().await?, action).await?;
            let link = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let data = resp.json::<Value>().await?;
            match data {
                Value::Array(items) => out.extend(items),
                Value::Object(ref o) => {
                    if let Some(items) = o.get("items").and_then(Value::as_array) {
                        out.extend(items.iter().cloned());
                    }
                }
                _ => {}
            }
            next = NEXT_LINK_RE.captures(&link).map(|c| c[1].to_string());
        }
        Ok(out)
    }

    // ---- ported review surface --------------------------------------------

    pub async fn get_pull_request(&self, pr_id: u64) -> Result<PullRequest, GitHubError> {
        let data = self
            .get_json(
                &self.repo_url(&format!("/pulls/{pr_id}")),
                "get_pull_request",
            )
            .await?;
        let head = data.get("head").cloned().unwrap_or(Value::Null);
        let base = data.get("base").cloned().unwrap_or(Value::Null);
        let getstr =
            |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(PullRequest {
            id: data.get("number").and_then(Value::as_u64).unwrap_or(pr_id),
            title: getstr(&data, "title"),
            description: data
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            source_branch: getstr(&head, "ref"),
            destination_branch: getstr(&base, "ref"),
            source_commit: getstr(&head, "sha"),
            destination_commit: getstr(&base, "sha"),
            author: data
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        })
    }

    pub async fn get_pull_request_diff(&self, pr_id: u64) -> Result<String, GitHubError> {
        let resp = self
            .http
            .get(self.repo_url(&format!("/pulls/{pr_id}")))
            .header(ACCEPT, ACCEPT_DIFF)
            .send()
            .await?;
        // 406 = diff exceeds 20k lines; fall back to /files reconstruction.
        if resp.status().as_u16() == 406 {
            tracing::info!("PR #{pr_id} diff > 20k lines; reconstructing from /files");
            return self.reconstruct_diff_from_files(pr_id).await;
        }
        let resp = Self::check(resp, "get_pull_request_diff").await?;
        Ok(resp.text().await?)
    }

    async fn reconstruct_diff_from_files(&self, pr_id: u64) -> Result<String, GitHubError> {
        let entries = self
            .paginate(
                self.repo_url(&format!("/pulls/{pr_id}/files")),
                "list_pr_files",
            )
            .await?;
        let mut chunks: Vec<String> = Vec::new();
        for entry in entries {
            let new = entry.get("filename").and_then(Value::as_str).unwrap_or("");
            if new.is_empty() {
                continue;
            }
            let old = entry
                .get("previous_filename")
                .and_then(Value::as_str)
                .unwrap_or(new);
            let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
            let patch = entry.get("patch").and_then(Value::as_str).unwrap_or("");

            let mut header = vec![format!("diff --git a/{old} b/{new}")];
            match status {
                "added" => header.push("new file mode 100644".into()),
                "removed" => header.push("deleted file mode 100644".into()),
                "renamed" if old != new => {
                    header.push("similarity index 100%".into());
                    header.push(format!("rename from {old}"));
                    header.push(format!("rename to {new}"));
                }
                _ => {}
            }
            if !patch.is_empty() {
                header.push(format!("--- a/{old}"));
                header.push(format!("+++ b/{new}"));
                chunks.push(format!("{}\n{}", header.join("\n"), patch));
            } else if status != "renamed" && status != "unchanged" {
                header.push("Binary files differ".into());
                chunks.push(header.join("\n"));
            }
        }
        Ok(chunks.join("\n"))
    }

    pub async fn list_comments(&self, pr_id: u64) -> Result<Vec<ExistingComment>, GitHubError> {
        let mut out = Vec::new();
        // 1. inline review comments
        for c in self
            .paginate(
                self.repo_url(&format!("/pulls/{pr_id}/comments")),
                "list_review_comments",
            )
            .await?
        {
            out.push(ExistingComment {
                id: c.get("id").and_then(Value::as_i64).unwrap_or(0),
                file: c.get("path").and_then(Value::as_str).map(String::from),
                line: c
                    .get("line")
                    .and_then(Value::as_u64)
                    .or_else(|| c.get("original_line").and_then(Value::as_u64))
                    .map(|n| n as u32),
                content: c
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                author: c
                    .get("user")
                    .and_then(|u| u.get("login"))
                    .and_then(Value::as_str)
                    .map(String::from),
            });
        }
        // 2. top-level issue comments
        for c in self
            .paginate(
                self.repo_url(&format!("/issues/{pr_id}/comments")),
                "list_issue_comments",
            )
            .await?
        {
            out.push(ExistingComment {
                id: c.get("id").and_then(Value::as_i64).unwrap_or(0),
                file: None,
                line: None,
                content: c
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                author: c
                    .get("user")
                    .and_then(|u| u.get("login"))
                    .and_then(Value::as_str)
                    .map(String::from),
            });
        }
        Ok(out)
    }

    pub async fn post_summary_comment(&self, pr_id: u64, body: &str) -> Result<Value, GitHubError> {
        let resp = self
            .http
            .post(self.repo_url(&format!("/issues/{pr_id}/comments")))
            .header(ACCEPT, ACCEPT_JSON)
            .json(&json!({ "body": body }))
            .send()
            .await?;
        let resp = Self::check(resp, "post_summary_comment").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    /// Create a completed GitHub Check Run so the review shows up as a
    /// pass/fail check alongside CI, not just a PR comment. `conclusion` is
    /// one of `success`/`failure`/`neutral` (GitHub's Checks API vocabulary).
    pub async fn create_check_run(
        &self,
        head_sha: &str,
        name: &str,
        conclusion: &str,
        title: &str,
        summary: &str,
    ) -> Result<Value, GitHubError> {
        let resp = self
            .http
            .post(self.repo_url("/check-runs"))
            .header(ACCEPT, ACCEPT_JSON)
            .json(&json!({
                "name": name,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": { "title": title, "summary": summary },
            }))
            .send()
            .await?;
        let resp = Self::check(resp, "create_check_run").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    pub async fn post_inline_comment(
        &self,
        pr_id: u64,
        comment: &InlineComment,
    ) -> Result<Value, GitHubError> {
        let commit_id = comment.commit_id.as_deref().ok_or(GitHubError::Invalid(
            "post_inline_comment requires commit_id (PR head sha)",
        ))?;
        let mut payload = json!({
            "body": comment.body,
            "commit_id": commit_id,
            "path": comment.file,
            "line": comment.line,
            "side": "RIGHT",
        });
        if let Some(start) = comment.start_line {
            if start < comment.line {
                payload["start_line"] = json!(start);
                payload["start_side"] = json!("RIGHT");
            }
        }
        let resp = self
            .http
            .post(self.repo_url(&format!("/pulls/{pr_id}/comments")))
            .header(ACCEPT, ACCEPT_JSON)
            .json(&payload)
            .send()
            .await?;
        let resp = Self::check(resp, "post_inline_comment").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    // ---- interactive surface ----------------------------------------------

    /// The login of the token's identity — what counts as "our" comments for
    /// reply detection (a GitHub App shows as `<slug>[bot]`).
    pub async fn authenticated_login(&self) -> Result<String, GitHubError> {
        let data = self
            .get_json(&format!("{}/user", self.base_url), "get_user")
            .await?;
        Ok(data
            .get("login")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string())
    }

    fn parse_review_comment(c: &Value) -> ReviewComment {
        ReviewComment {
            id: c.get("id").and_then(Value::as_i64).unwrap_or(0),
            in_reply_to_id: c.get("in_reply_to_id").and_then(Value::as_i64),
            body: c
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            path: c.get("path").and_then(Value::as_str).map(String::from),
            line: c
                .get("line")
                .and_then(Value::as_u64)
                .or_else(|| c.get("original_line").and_then(Value::as_u64))
                .map(|n| n as u32),
            user: c
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            diff_hunk: c.get("diff_hunk").and_then(Value::as_str).map(String::from),
        }
    }

    pub async fn list_review_comments(
        &self,
        pr_id: u64,
    ) -> Result<Vec<ReviewComment>, GitHubError> {
        let raw = self
            .paginate(
                self.repo_url(&format!("/pulls/{pr_id}/comments")),
                "list_review_comments",
            )
            .await?;
        Ok(raw.iter().map(Self::parse_review_comment).collect())
    }

    pub async fn get_review_comment(&self, comment_id: i64) -> Result<ReviewComment, GitHubError> {
        let data = self
            .get_json(
                &self.repo_url(&format!("/pulls/comments/{comment_id}")),
                "get_review_comment",
            )
            .await?;
        Ok(Self::parse_review_comment(&data))
    }

    pub async fn list_issue_comments(&self, pr_id: u64) -> Result<Vec<IssueComment>, GitHubError> {
        let raw = self
            .paginate(
                self.repo_url(&format!("/issues/{pr_id}/comments")),
                "list_issue_comments",
            )
            .await?;
        Ok(raw
            .iter()
            .map(|c| IssueComment {
                id: c.get("id").and_then(Value::as_i64).unwrap_or(0),
                body: c
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                user: c
                    .get("user")
                    .and_then(|u| u.get("login"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
            .collect())
    }

    /// Reply inside an existing inline review-comment thread. `comment_id` must
    /// be a TOP-LEVEL review comment (GitHub rejects replies-to-replies).
    pub async fn reply_to_review_comment(
        &self,
        pr_id: u64,
        comment_id: i64,
        body: &str,
    ) -> Result<Value, GitHubError> {
        let resp = self
            .http
            .post(self.repo_url(&format!("/pulls/{pr_id}/comments/{comment_id}/replies")))
            .header(ACCEPT, ACCEPT_JSON)
            .json(&json!({ "body": body }))
            .send()
            .await?;
        let resp = Self::check(resp, "reply_to_review_comment").await?;
        Ok(resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    /// Post a top-level PR comment, returning its id (so the caller can track
    /// its own comments).
    pub async fn post_issue_comment(&self, pr_id: u64, body: &str) -> Result<i64, GitHubError> {
        let data = self.post_summary_comment(pr_id, body).await?;
        Ok(data.get("id").and_then(Value::as_i64).unwrap_or(0))
    }

    /// Open a PR (fix flow, "new branch" strategy). Returns (number, html_url).
    pub async fn create_pull_request(
        &self,
        title: &str,
        head: &str,
        base: &str,
        body: &str,
    ) -> Result<(u64, String), GitHubError> {
        let resp = self
            .http
            .post(self.repo_url("/pulls"))
            .header(ACCEPT, ACCEPT_JSON)
            .json(&json!({ "title": title, "head": head, "base": base, "body": body }))
            .send()
            .await?;
        let resp = Self::check(resp, "create_pull_request").await?;
        let data = resp.json::<Value>().await?;
        Ok((
            data.get("number").and_then(Value::as_u64).unwrap_or(0),
            data.get("html_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client(base_url: &str) -> GitHubClient {
        GitHubClient::new("test-token", "octo", "widget", base_url, 5.0).expect("client")
    }

    #[tokio::test]
    async fn create_check_run_posts_expected_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/octo/widget/check-runs"))
            .and(body_json(serde_json::json!({
                "name": "bugbot review",
                "head_sha": "abc123",
                "status": "completed",
                "conclusion": "success",
                "output": { "title": "No findings", "summary": "all clean" },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 1,
                "conclusion": "success"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let resp = client
            .create_check_run(
                "abc123",
                "bugbot review",
                "success",
                "No findings",
                "all clean",
            )
            .await
            .expect("create check run");
        assert_eq!(
            resp.get("conclusion").and_then(Value::as_str),
            Some("success")
        );
    }

    #[tokio::test]
    async fn create_check_run_surfaces_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/octo/widget/check-runs"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "Resource not accessible by integration"
            })))
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client
            .create_check_run("abc123", "bugbot review", "success", "t", "s")
            .await
            .expect_err("missing Checks permission should error, not panic");
        assert!(matches!(err, GitHubError::Api { status: 422, .. }));
    }
}
