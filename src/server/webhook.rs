//! Bitbucket Cloud webhook event extractor. Ported from `server/webhook.py`.
//! We trigger reviews only on `pullrequest:created` / `:updated`.

use serde_json::Value;

pub const BB_TRIGGER_EVENTS: &[&str] = &["pullrequest:created", "pullrequest:updated"];

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WebhookParseError(pub String);

fn err(msg: impl Into<String>) -> WebhookParseError {
    WebhookParseError(msg.into())
}

#[derive(Debug, Clone)]
pub struct BitbucketEvent {
    pub event_key: String,
    pub workspace: String,
    pub repo_slug: String,
    pub pr_id: u64,
    pub actor: String,
    pub is_trigger: bool,
}

pub fn parse_bitbucket(
    event_key: Option<&str>,
    payload: &Value,
) -> Result<BitbucketEvent, WebhookParseError> {
    let event_key = event_key.ok_or_else(|| err("missing X-Event-Key header"))?;
    if !event_key.starts_with("pullrequest:") {
        return Err(err(format!("unsupported event family: {event_key}")));
    }

    let full_name = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (workspace, repo_slug) = full_name.split_once('/').ok_or_else(|| {
        err(format!(
            "repository.full_name missing or invalid: {full_name:?}"
        ))
    })?;

    let pr_id = payload
        .get("pullrequest")
        .and_then(|p| p.get("id"))
        .and_then(Value::as_u64)
        .ok_or_else(|| err("pullrequest.id missing or not int"))?;

    let actor = payload
        .get("actor")
        .and_then(|a| a.get("display_name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    Ok(BitbucketEvent {
        event_key: event_key.to_string(),
        workspace: workspace.to_string(),
        repo_slug: repo_slug.to_string(),
        pr_id,
        actor,
        is_trigger: BB_TRIGGER_EVENTS.contains(&event_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_pr_created_as_trigger() {
        let payload = json!({
            "repository": {"full_name": "ws/repo"},
            "pullrequest": {"id": 42},
            "actor": {"display_name": "alice"}
        });
        let ev = parse_bitbucket(Some("pullrequest:created"), &payload).unwrap();
        assert_eq!(ev.pr_id, 42);
        assert_eq!(ev.workspace, "ws");
        assert!(ev.is_trigger);
    }

    #[test]
    fn non_trigger_event_parsed_but_not_trigger() {
        let payload = json!({"repository": {"full_name": "ws/repo"}, "pullrequest": {"id": 1}});
        let ev = parse_bitbucket(Some("pullrequest:approved"), &payload).unwrap();
        assert!(!ev.is_trigger);
    }

    #[test]
    fn rejects_non_pr_event() {
        assert!(parse_bitbucket(Some("repo:push"), &json!({})).is_err());
        assert!(parse_bitbucket(None, &json!({})).is_err());
    }
}
