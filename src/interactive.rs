//! GitHub interactivity: respond to PR comments (Q&A), commands
//! (`@bugbot review` / `bugbot run` / `cursor review`, `@bugbot fix …`,
//! `@bugbot help`) and apply fixes. This is the capability Cursor BugBot
//! itself lacks (in-thread conversation) — the headline of this rewrite.
//!
//! Stateless by design: each inbound comment re-clones the PR and assembles
//! the thread into the prompt, rather than resuming a session (clones are
//! ephemeral and the model must see current code).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::clients::github::{GitHubClient, ReviewComment};
use crate::clients::llm::{LlmBackend, LlmMode, LlmRequest};
use crate::clients::provider::Provider;
use crate::config::{FixBranchStrategy, Settings};
use crate::libs::redact::redact;
use crate::prompts;
use crate::review::Reviewer;
use crate::server::webhook_github::{CommentKind, GithubComment};
use crate::services::repo::{self, clone_pr_branch, run_git, CloneOptions};

/// In-memory autofix rate-limiter (max N per PR per rolling window). Resets on
/// process restart — acceptable for a self-hosted bot.
pub struct FixLimiter {
    max: u32,
    window: Duration,
    inner: Mutex<HashMap<(String, String, u64), Vec<Instant>>>,
}

impl FixLimiter {
    pub fn new(max: u32) -> Self {
        FixLimiter {
            max,
            window: Duration::from_secs(24 * 3600),
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// True if this PR is still under the limit. Does NOT record an attempt —
    /// call [`record`](Self::record) once the attempt actually reaches the
    /// protected resource (the LLM run), so transient pre-LLM failures (e.g. a
    /// clone error) don't burn a 24h slot. The check→record gap allows a
    /// benign race (two concurrent fixes on one PR may both pass `check`), but
    /// the worker dedupes interact jobs per comment, so it tops out at max+1.
    pub async fn check(&self, owner: &str, repo: &str, pr: u64) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let entry = map
            .entry((owner.to_string(), repo.to_string(), pr))
            .or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        (entry.len() as u32) < self.max
    }

    /// Record one autofix attempt against the rolling per-PR window.
    pub async fn record(&self, owner: &str, repo: &str, pr: u64) {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let entry = map
            .entry((owner.to_string(), repo.to_string(), pr))
            .or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        entry.push(now);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Review,
    Fix(Option<String>),
    Help,
    Converse,
    None,
}

fn parse_command(body: &str, is_reply_to_bot: bool, bot_login: &str) -> Command {
    let lower = body.to_lowercase();
    if lower.contains("bugbot run") || lower.contains("cursor review") {
        return Command::Review;
    }
    // @bugbot <verb> [rest], or @<bot_login> <verb> [rest]
    let alt = if bot_login.is_empty() {
        "bugbot".to_string()
    } else {
        format!("bugbot|{}", regex::escape(bot_login))
    };
    if let Ok(re) = regex::Regex::new(&format!(r"(?i)@(?:{alt})\s+([a-zA-Z]+)[ \t]*(.*)")) {
        if let Some(c) = re.captures(body) {
            let verb = c[1].to_lowercase();
            let rest = c
                .get(2)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            return match verb.as_str() {
                "review" | "run" => Command::Review,
                "fix" => Command::Fix(if rest.is_empty() { None } else { Some(rest) }),
                "help" => Command::Help,
                _ => Command::Converse,
            };
        }
    }
    let mentioned = lower.contains("@bugbot")
        || (!bot_login.is_empty() && lower.contains(&format!("@{}", bot_login.to_lowercase())));
    if mentioned || is_reply_to_bot {
        return Command::Converse;
    }
    Command::None
}

fn help_text(bot_marker: &str) -> String {
    format!(
        "**bugbot commands**\n\n\
         - `@bugbot review` (or `bugbot run` / `cursor review`) — re-review this PR\n\
         - `@bugbot fix <instruction>` — apply a fix (opens a branch/PR or commits to this branch)\n\
         - reply to any bugbot comment, or `@bugbot <question>` — ask a follow-up and I'll answer in-thread\n\
         - `@bugbot help` — this message\n\n\
         _— bugbot · `{bot_marker}`_"
    )
}

/// Handle one inbound PR comment. `gh` is consumed (the review path wraps it in
/// a `Provider`).
pub async fn handle_comment(
    s: &Settings,
    gh: GitHubClient,
    llm: &LlmBackend,
    c: &GithubComment,
    fix_limiter: &FixLimiter,
) -> anyhow::Result<()> {
    // Resolve our own identity for loop-guarding + reply detection.
    let bot_login = match &s.github_bot_login {
        Some(l) => l.clone(),
        None => gh.authenticated_login().await.unwrap_or_default(),
    };

    // Loop guard: never react to our own comments.
    if !bot_login.is_empty() && c.actor.eq_ignore_ascii_case(&bot_login) {
        tracing::debug!(
            "ignoring our own comment on {}/{}#{}",
            c.workspace,
            c.repo_slug,
            c.pr_id
        );
        return Ok(());
    }

    // For inline replies, decide if the parent (thread root) is ours.
    let (is_reply_to_bot, thread) = match c.kind {
        CommentKind::ReviewReply => {
            let all = gh.list_review_comments(c.pr_id).await.unwrap_or_default();
            // Resolve the TRUE thread root by following in_reply_to_id up the
            // chain. GitHub usually normalizes replies to point at the
            // top-level comment, but a reply-to-reply can carry a non-root
            // parent — walking guarantees bot-thread detection, the transcript
            // filter, and reply_to_review_comment all use the top-level id.
            let mut root_id = c.in_reply_to_id.unwrap_or(c.comment_id);
            for _ in 0..256 {
                match all
                    .iter()
                    .find(|rc| rc.id == root_id)
                    .and_then(|rc| rc.in_reply_to_id)
                {
                    Some(parent) if parent != root_id => root_id = parent,
                    _ => break,
                }
            }
            let root_is_bot = all
                .iter()
                .find(|rc| rc.id == root_id)
                .map(|rc| !bot_login.is_empty() && rc.user.eq_ignore_ascii_case(&bot_login))
                .unwrap_or(false);
            let mut t: Vec<ReviewComment> = all
                .into_iter()
                .filter(|rc| rc.id == root_id || rc.in_reply_to_id == Some(root_id))
                .collect();
            t.sort_by_key(|rc| rc.id);
            (root_is_bot, Some((root_id, t)))
        }
        CommentKind::Issue => (false, None),
    };

    let command = parse_command(&c.body, is_reply_to_bot, &bot_login);
    tracing::info!(
        "interactive {}/{}#{} from {} → {:?}",
        c.workspace,
        c.repo_slug,
        c.pr_id,
        c.actor,
        command
    );

    match command {
        Command::None => Ok(()),
        Command::Help => {
            post_reply(
                &gh,
                c,
                thread.as_ref().map(|(r, _)| *r),
                &help_text(&s.bot_marker),
            )
            .await
        }
        Command::Review => {
            tracing::info!(
                "re-review requested on {}/{}#{}",
                c.workspace,
                c.repo_slug,
                c.pr_id
            );
            // Re-review with the focus domain from the webhook URL suffix, not
            // the global default, so it matches the original automated review.
            let domain = if c.domain.is_empty() {
                s.default_domain.as_str()
            } else {
                c.domain.as_str()
            };
            let provider = Provider::GitHub(gh);
            Reviewer::new(s, &provider, llm)
                .run(c.pr_id, domain)
                .await?;
            Ok(())
        }
        Command::Converse => handle_converse(s, &gh, llm, c, thread).await,
        Command::Fix(instruction) => {
            handle_fix(s, &gh, llm, c, thread, instruction, fix_limiter).await
        }
    }
}

/// Post a reply: in-thread for inline review comments, top-level otherwise.
async fn post_reply(
    gh: &GitHubClient,
    c: &GithubComment,
    thread_root: Option<i64>,
    body: &str,
) -> anyhow::Result<()> {
    match (c.kind, thread_root) {
        (CommentKind::ReviewReply, Some(root)) => {
            gh.reply_to_review_comment(c.pr_id, root, body).await?;
        }
        _ => {
            gh.post_issue_comment(c.pr_id, body).await?;
        }
    }
    Ok(())
}

fn attribution(llm: &LlmBackend, marker: &str) -> String {
    format!("\n\n_— {} · `{}`_", llm.display_name(), marker)
}

async fn handle_converse(
    s: &Settings,
    gh: &GitHubClient,
    llm: &LlmBackend,
    c: &GithubComment,
    thread: Option<(i64, Vec<ReviewComment>)>,
) -> anyhow::Result<()> {
    let pr = gh.get_pull_request(c.pr_id).await?;
    let diff = gh.get_pull_request_diff(c.pr_id).await.unwrap_or_default();
    let safe_diff = redact(&truncate(&diff, s.max_diff_chars));

    // Build the conversation transcript.
    let mut transcript = String::new();
    match (&c.kind, &thread) {
        (CommentKind::ReviewReply, Some((_, t))) => {
            if let Some(first) = t.first() {
                if let (Some(path), Some(line)) = (&first.path, first.line) {
                    transcript.push_str(&format!("(inline thread on `{path}:{line}`)\n\n"));
                }
            }
            for rc in t {
                transcript.push_str(&format!("**{}**: {}\n\n", rc.user, rc.body.trim()));
            }
        }
        _ => {
            // Top-level: include recent issue comments for context.
            let issue_comments = gh.list_issue_comments(c.pr_id).await.unwrap_or_default();
            for ic in issue_comments.iter().rev().take(8).rev() {
                transcript.push_str(&format!("**{}**: {}\n\n", ic.user, ic.body.trim()));
            }
            // Ensure the triggering comment is present.
            if !transcript.contains(c.body.trim()) {
                transcript.push_str(&format!("**{}**: {}\n\n", c.actor, c.body.trim()));
            }
        }
    }

    let user_prompt = format!(
        "# Pull request\n\
         **Title:** {title}\n**Author:** {author}\n**Branch:** `{src}` → `{dst}`\n\n\
         ## Unified diff (truncated)\n```diff\n{diff}\n```\n\n\
         ## Conversation thread (oldest first)\n{transcript}\n\
         ## Task\nReply to the newest message above (from **{actor}**). Follow the system rules.",
        title = pr.title,
        author = pr.author,
        src = pr.source_branch,
        dst = pr.destination_branch,
        diff = safe_diff,
        transcript = transcript,
        actor = c.actor,
    );

    let clone = clone_for(s, gh, &pr.source_branch, false).await;
    let cwd = clone.as_ref().map(|cl| cl.path.clone());

    let req = LlmRequest {
        system_prompt: prompts::REPLY.to_string(),
        user_prompt,
        cwd,
        mode: LlmMode::Reply,
        output_schema: None,
        timeout: Duration::from_secs_f64(s.codex_timeout_seconds.max(s.claude_timeout_seconds)),
    };

    let reply = match llm.run(&req).await {
        Ok(r) => r.content,
        Err(e) => {
            tracing::error!("converse LLM failed: {e}");
            "I hit an error trying to answer that — please try again.".to_string()
        }
    };
    drop(clone);

    let body = format!("{}{}", reply.trim(), attribution(llm, &s.bot_marker));
    post_reply(gh, c, thread.as_ref().map(|(r, _)| *r), &body).await
}

async fn handle_fix(
    s: &Settings,
    gh: &GitHubClient,
    llm: &LlmBackend,
    c: &GithubComment,
    thread: Option<(i64, Vec<ReviewComment>)>,
    instruction: Option<String>,
    fix_limiter: &FixLimiter,
) -> anyhow::Result<()> {
    let root = thread.as_ref().map(|(r, _)| *r);
    if !s.fix_enabled {
        return post_reply(gh, c, root, "Autofix is disabled on this bugbot instance.").await;
    }
    if !fix_limiter.check(&c.workspace, &c.repo_slug, c.pr_id).await {
        return post_reply(
            gh,
            c,
            root,
            &format!(
                "Autofix limit reached for this PR ({} per 24h). Try again later.",
                s.fix_max_per_pr_24h
            ),
        )
        .await;
    }

    let pr = gh.get_pull_request(c.pr_id).await?;
    let diff = gh.get_pull_request_diff(c.pr_id).await.unwrap_or_default();
    let safe_diff = redact(&truncate(&diff, s.max_diff_chars));

    // Context: the explicit instruction, plus the finding being replied to.
    let mut request_block = match &instruction {
        Some(i) if !i.is_empty() => format!("A maintainer (@{}) asked: \"{}\"", c.actor, i),
        _ => format!(
            "A maintainer (@{}) asked you to fix the issue discussed in this thread.",
            c.actor
        ),
    };
    if let Some((_, t)) = &thread {
        if let Some(first) = t.first() {
            if let (Some(path), Some(line)) = (&first.path, first.line) {
                request_block.push_str(&format!(
                    "\n\nThe thread is on `{path}:{line}`. The original bugbot finding was:\n> {}",
                    first.body.trim().replace('\n', "\n> ")
                ));
            }
        }
    }

    let user_prompt = format!(
        "# Fix request\n\
         **PR:** {title} (`{src}` → `{dst}`)\n\n\
         {request}\n\n\
         ## Unified diff of the PR (for context)\n```diff\n{diff}\n```\n\n\
         ## Task\nApply the fix in the working tree per the system rules, then summarise what you changed.",
        title = pr.title,
        src = pr.source_branch,
        dst = pr.destination_branch,
        request = request_block,
        diff = safe_diff,
    );

    // Fix needs real blobs (to commit/push) → no blob filter.
    let clone = match clone_for(s, gh, &pr.source_branch, true).await {
        Some(c) => c,
        None => {
            return post_reply(
                gh,
                c,
                root,
                "I couldn't clone the PR branch to apply a fix.",
            )
            .await;
        }
    };
    repo::scrub_injection_files(&clone.path);

    // Charge a slot now that we're about to invoke the LLM — the expensive,
    // abuse-prone step. The pre-LLM failure above (a clone error) returns early
    // without consuming the per-PR quota.
    fix_limiter
        .record(&c.workspace, &c.repo_slug, c.pr_id)
        .await;

    let req = LlmRequest {
        system_prompt: prompts::FIX.to_string(),
        user_prompt,
        cwd: Some(clone.path.clone()),
        mode: LlmMode::Fix,
        output_schema: None,
        timeout: Duration::from_secs_f64(s.codex_timeout_seconds),
    };
    let model_msg = match llm.run(&req).await {
        Ok(r) => r.content,
        Err(e) => {
            tracing::error!("fix LLM failed: {e}");
            drop(clone);
            return post_reply(gh, c, root, &format!("I couldn't apply the fix: {e}")).await;
        }
    };

    // Did anything change?
    let status = run_git(
        "status",
        &["status", "--porcelain"],
        Some(&clone.path),
        &[],
        Duration::from_secs(30),
    )
    .await;
    let dirty = matches!(&status, Ok(o) if !String::from_utf8_lossy(&o.stdout).trim().is_empty());
    if !dirty {
        drop(clone);
        let body = format!(
            "No changes were necessary.\n\n{}{}",
            model_msg.trim(),
            attribution(llm, &s.bot_marker)
        );
        return post_reply(gh, c, root, &body).await;
    }

    let push_result =
        commit_and_push(s, &clone.path, &pr.source_branch, c.pr_id, c.comment_id).await;
    drop(clone);

    let body = match push_result {
        Ok(PushOutcome::ExistingBranch) => format!(
            "✅ Pushed a fix to `{}`.\n\n{}{}",
            pr.source_branch,
            model_msg.trim(),
            attribution(llm, &s.bot_marker)
        ),
        Ok(PushOutcome::NewBranch { branch }) => {
            // Open a PR from the fix branch into the PR's source branch.
            let title = format!("bugbot fix for #{}", c.pr_id);
            let pr_body = format!(
                "Automated fix requested by @{}.\n\n{}",
                c.actor,
                model_msg.trim()
            );
            match gh
                .create_pull_request(&title, &branch, &pr.source_branch, &pr_body)
                .await
            {
                Ok((num, url)) => format!(
                    "✅ Opened fix PR [#{num}]({url}) targeting `{}`.\n\n{}{}",
                    pr.source_branch,
                    model_msg.trim(),
                    attribution(llm, &s.bot_marker)
                ),
                Err(e) => format!(
                    "I pushed the fix to `{branch}` but couldn't open a PR: {e}\n\n{}{}",
                    model_msg.trim(),
                    attribution(llm, &s.bot_marker)
                ),
            }
        }
        Err(e) => {
            tracing::error!("fix push failed: {e}");
            format!(
                "I made the changes but couldn't push them: {e}\n\n{}{}",
                model_msg.trim(),
                attribution(llm, &s.bot_marker)
            )
        }
    };
    post_reply(gh, c, root, &body).await
}

enum PushOutcome {
    ExistingBranch,
    NewBranch { branch: String },
}

async fn commit_and_push(
    s: &Settings,
    clone_path: &std::path::Path,
    source_branch: &str,
    pr_id: u64,
    comment_id: i64,
) -> anyhow::Result<PushOutcome> {
    let identity: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME", "bugbot"),
        ("GIT_AUTHOR_EMAIL", "bugbot@users.noreply.github.com"),
        ("GIT_COMMITTER_NAME", "bugbot"),
        ("GIT_COMMITTER_EMAIL", "bugbot@users.noreply.github.com"),
    ];
    let t = Duration::from_secs_f64(s.git_clone_timeout_seconds);

    let (target_ref, outcome) = match s.fix_branch_strategy {
        FixBranchStrategy::NewBranch => {
            let branch = format!("bugbot/fix-pr{pr_id}-{comment_id}");
            run_git(
                "checkout",
                &["checkout", "-b", &branch],
                Some(clone_path),
                &[],
                t,
            )
            .await?;
            (
                format!("HEAD:refs/heads/{branch}"),
                PushOutcome::NewBranch { branch },
            )
        }
        FixBranchStrategy::ExistingBranch => {
            (format!("HEAD:{source_branch}"), PushOutcome::ExistingBranch)
        }
    };

    run_git("add", &["add", "-A"], Some(clone_path), identity, t).await?;
    let msg = format!("bugbot: automated fix for #{pr_id}");
    run_git(
        "commit",
        &["commit", "-m", &msg],
        Some(clone_path),
        identity,
        t,
    )
    .await?;
    // origin already carries the credentialed URL from the clone.
    run_git(
        "push",
        &["push", "origin", &target_ref],
        Some(clone_path),
        identity,
        t,
    )
    .await?;
    Ok(outcome)
}

async fn clone_for(
    s: &Settings,
    gh: &GitHubClient,
    branch: &str,
    for_fix: bool,
) -> Option<crate::services::repo::ClonedRepo> {
    let opts = CloneOptions {
        host: gh.clone_host().to_string(),
        workspace: gh.owner().to_string(),
        repo_slug: gh.repo().to_string(),
        branch: branch.to_string(),
        username: gh.clone_username().to_string(),
        token: gh.token().to_string(),
        depth: s.git_clone_depth,
        max_mb: s.git_clone_max_mb,
        timeout: Duration::from_secs_f64(s.git_clone_timeout_seconds),
        blob_filter: !for_fix,
    };
    match clone_pr_branch(&opts).await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("interactive clone failed: {e}");
            None
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    format!("{}\n… [truncated]", &s[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_review_triggers() {
        assert_eq!(
            parse_command("please bugbot run now", false, "bugbot-app"),
            Command::Review
        );
        assert_eq!(parse_command("cursor review", false, ""), Command::Review);
        assert_eq!(parse_command("@bugbot review", false, "x"), Command::Review);
    }

    #[test]
    fn parse_fix_with_instruction() {
        assert_eq!(
            parse_command(
                "@bugbot fix use a parameterised query",
                false,
                "bugbot[bot]"
            ),
            Command::Fix(Some("use a parameterised query".to_string()))
        );
        assert_eq!(parse_command("@bugbot fix", false, ""), Command::Fix(None));
    }

    #[test]
    fn parse_converse_on_mention_or_reply() {
        assert_eq!(
            parse_command("@bugbot what about null?", false, ""),
            Command::Converse
        );
        assert_eq!(
            parse_command("but the input is validated upstream", true, ""),
            Command::Converse
        );
        assert_eq!(
            parse_command("unrelated chatter", false, "bugbot[bot]"),
            Command::None
        );
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse_command("@bugbot help", false, ""), Command::Help);
    }

    #[tokio::test]
    async fn fix_limiter_caps_attempts() {
        let l = FixLimiter::new(2);
        assert!(l.check("o", "r", 1).await);
        l.record("o", "r", 1).await;
        assert!(l.check("o", "r", 1).await);
        l.record("o", "r", 1).await;
        assert!(!l.check("o", "r", 1).await); // over the cap, not recorded
        assert!(l.check("o", "r", 2).await); // different PR
        l.record("o", "r", 2).await;
    }
}
