//! GitHub webhook event extractor. Ports `server/webhook_github.py` and adds
//! the comment events that drive interactivity (Q&A + commands + fixes).
//!
//! Events we care about:
//!   * pull_request (opened/reopened/synchronize/ready_for_review) → review
//!   * issue_comment (created, on a PR)                            → command/Q&A
//!   * pull_request_review_comment (created)                       → in-thread reply
//!
//! Everything else parses to `Ignore` so the handler can 204 it.

use serde_json::Value;

use crate::server::webhook::WebhookParseError;

fn err(msg: impl Into<String>) -> WebhookParseError {
    WebhookParseError(msg.into())
}

pub const GH_TRIGGER_ACTIONS: &[&str] = &["opened", "reopened", "synchronize", "ready_for_review"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// Top-level PR (issue) comment.
    Issue,
    /// Reply on an inline review-comment thread.
    ReviewReply,
}

#[derive(Debug, Clone)]
pub struct GithubComment {
    pub workspace: String,
    pub repo_slug: String,
    pub pr_id: u64,
    pub actor: String,
    pub kind: CommentKind,
    pub comment_id: i64,
    pub in_reply_to_id: Option<i64>,
    pub body: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    /// Focus domain resolved from the webhook URL suffix (e.g. `/webhook/github/data-eng`).
    /// Set by the server before dispatch; empty when the request carried no suffix.
    pub domain: String,
}

#[derive(Debug, Clone)]
pub enum GithubEvent {
    /// A PR open/update that should be reviewed.
    PrTrigger {
        workspace: String,
        repo_slug: String,
        pr_id: u64,
        action: String,
        actor: String,
    },
    /// A human comment we may respond to.
    Comment(GithubComment),
    /// Recognised but non-actionable.
    Ignore(String),
}

fn repo_owner_slug(payload: &Value) -> Result<(String, String), WebhookParseError> {
    let full_name = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    full_name
        .split_once('/')
        .map(|(o, r)| (o.to_string(), r.to_string()))
        .ok_or_else(|| {
            err(format!(
                "repository.full_name missing or invalid: {full_name:?}"
            ))
        })
}

pub fn parse_github(
    event_header: Option<&str>,
    payload: &Value,
) -> Result<GithubEvent, WebhookParseError> {
    let header = event_header.ok_or_else(|| err("missing X-GitHub-Event header"))?;
    match header {
        "ping" => Ok(GithubEvent::Ignore("ping".into())),
        "pull_request" => parse_pull_request(payload),
        "issue_comment" => parse_issue_comment(payload),
        "pull_request_review_comment" => parse_review_comment(payload),
        other => Ok(GithubEvent::Ignore(format!(
            "unsupported event family: {other}"
        ))),
    }
}

fn parse_pull_request(payload: &Value) -> Result<GithubEvent, WebhookParseError> {
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if action.is_empty() {
        return Err(err("pull_request payload missing 'action'"));
    }
    let (workspace, repo_slug) = repo_owner_slug(payload)?;
    let pr = payload.get("pull_request").cloned().unwrap_or(Value::Null);
    let pr_id = pr
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("pull_request.number missing or not int"))?;
    let actor = payload
        .get("sender")
        .and_then(|s| s.get("login"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let mut is_trigger = GH_TRIGGER_ACTIONS.contains(&action.as_str());
    // Draft PRs: opened+draft → wait for ready_for_review.
    if action == "opened" && pr.get("draft").and_then(Value::as_bool) == Some(true) {
        is_trigger = false;
    }
    if !is_trigger {
        return Ok(GithubEvent::Ignore(format!("pull_request:{action}")));
    }
    Ok(GithubEvent::PrTrigger {
        workspace,
        repo_slug,
        pr_id,
        action,
        actor,
    })
}

fn parse_issue_comment(payload: &Value) -> Result<GithubEvent, WebhookParseError> {
    let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
    if action != "created" {
        return Ok(GithubEvent::Ignore(format!("issue_comment:{action}")));
    }
    let issue = payload.get("issue").cloned().unwrap_or(Value::Null);
    // Only PRs have `issue.pull_request`.
    if issue.get("pull_request").is_none() {
        return Ok(GithubEvent::Ignore("issue_comment on non-PR issue".into()));
    }
    let (workspace, repo_slug) = repo_owner_slug(payload)?;
    let pr_id = issue
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("issue.number missing"))?;
    let comment = payload.get("comment").cloned().unwrap_or(Value::Null);
    Ok(GithubEvent::Comment(GithubComment {
        workspace,
        repo_slug,
        pr_id,
        actor: comment
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        kind: CommentKind::Issue,
        comment_id: comment.get("id").and_then(Value::as_i64).unwrap_or(0),
        in_reply_to_id: None,
        body: comment
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        path: None,
        line: None,
        domain: String::new(),
    }))
}

fn parse_review_comment(payload: &Value) -> Result<GithubEvent, WebhookParseError> {
    let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
    if action != "created" {
        return Ok(GithubEvent::Ignore(format!(
            "pull_request_review_comment:{action}"
        )));
    }
    let (workspace, repo_slug) = repo_owner_slug(payload)?;
    let pr_id = payload
        .get("pull_request")
        .and_then(|p| p.get("number"))
        .and_then(Value::as_u64)
        .ok_or_else(|| err("pull_request.number missing"))?;
    let comment = payload.get("comment").cloned().unwrap_or(Value::Null);
    Ok(GithubEvent::Comment(GithubComment {
        workspace,
        repo_slug,
        pr_id,
        actor: comment
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        kind: CommentKind::ReviewReply,
        comment_id: comment.get("id").and_then(Value::as_i64).unwrap_or(0),
        in_reply_to_id: comment.get("in_reply_to_id").and_then(Value::as_i64),
        body: comment
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        path: comment
            .get("path")
            .and_then(Value::as_str)
            .map(String::from),
        line: comment
            .get("line")
            .and_then(Value::as_u64)
            .or_else(|| comment.get("original_line").and_then(Value::as_u64))
            .map(|n| n as u32),
        domain: String::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pr_opened_triggers_unless_draft() {
        let p = json!({"action":"opened","repository":{"full_name":"o/r"},"pull_request":{"number":7,"draft":false},"sender":{"login":"bob"}});
        assert!(matches!(
            parse_github(Some("pull_request"), &p),
            Ok(GithubEvent::PrTrigger { pr_id: 7, .. })
        ));
        let draft = json!({"action":"opened","repository":{"full_name":"o/r"},"pull_request":{"number":7,"draft":true},"sender":{"login":"bob"}});
        assert!(matches!(
            parse_github(Some("pull_request"), &draft),
            Ok(GithubEvent::Ignore(_))
        ));
    }

    #[test]
    fn issue_comment_on_pr_is_comment() {
        let p = json!({"action":"created","repository":{"full_name":"o/r"},"issue":{"number":3,"pull_request":{}},"comment":{"id":99,"body":"@bugbot review","user":{"login":"carol"}}});
        match parse_github(Some("issue_comment"), &p).unwrap() {
            GithubEvent::Comment(c) => {
                assert_eq!(c.pr_id, 3);
                assert_eq!(c.kind, CommentKind::Issue);
                assert_eq!(c.body, "@bugbot review");
            }
            _ => panic!("expected comment"),
        }
    }

    #[test]
    fn issue_comment_on_plain_issue_ignored() {
        let p = json!({"action":"created","repository":{"full_name":"o/r"},"issue":{"number":3},"comment":{"id":1,"body":"hi","user":{"login":"x"}}});
        assert!(matches!(
            parse_github(Some("issue_comment"), &p),
            Ok(GithubEvent::Ignore(_))
        ));
    }

    #[test]
    fn review_comment_reply_carries_in_reply_to() {
        let p = json!({"action":"created","repository":{"full_name":"o/r"},"pull_request":{"number":5},"comment":{"id":200,"in_reply_to_id":150,"body":"why?","path":"a.rs","line":12,"user":{"login":"dave"}}});
        match parse_github(Some("pull_request_review_comment"), &p).unwrap() {
            GithubEvent::Comment(c) => {
                assert_eq!(c.kind, CommentKind::ReviewReply);
                assert_eq!(c.in_reply_to_id, Some(150));
                assert_eq!(c.path.as_deref(), Some("a.rs"));
            }
            _ => panic!("expected comment"),
        }
    }
}
