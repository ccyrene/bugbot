# Handoff: two pending bugbot features

> **No secrets in this file.** All tokens / API tokens / webhook secrets / the
> GitHub App private key / account emails live ONLY in the VM's `~/bugbot/deploy/.env`
> (chmod 600) and the GitHub App settings. This handoff is intentionally credential-free.

**Context:** bugbot is LIVE in production (v0.4.1) — see `CLAUDE.md`. GitHub App
`himari-ai[bot]`, LLM = Claude **Opus 4.8** (primary) → **codex gpt-5.5** (failover),
GHCR + Watchtower pull-based CD. GitHub auto-review is verified working (posts as the
bot with a `— Claude Opus 4.8 · <n> tokens` footer). Two items remain.

---

## 1. Bitbucket: Atlassian API token needs a different git-clone username than REST

### Symptom
Bitbucket is enabled (`/healthz` → `bitbucket:true`) using an **Atlassian API token**
(`id.atlassian.com` → API tokens with Bitbucket scopes). REST API calls succeed, but
the **git clone over HTTPS fails to authenticate** → a review can't clone the repo, so
it degrades to scanner-findings-only (no LLM review).

### Root cause
Atlassian API tokens require **different usernames per transport**:

| transport | username that works | result |
|---|---|---|
| REST API (Basic auth) | the account **email** | 200 OK |
| git over HTTPS | `x-bitbucket-api-token-auth` | OK |
| `x-token-auth` | — | works only for Bitbucket *Access Tokens*, NOT API tokens |

bugbot uses a **single** `BUGBOT_BITBUCKET_USERNAME` for BOTH the REST client and the
git clone URL → it can satisfy only one transport at a time (email → REST works, clone
fails; `x-bitbucket-api-token-auth` → clone works, REST 401s).

(Verified empirically against a real private repo: REST `GET /2.0/repositories/{ws}/{repo}`
with `email:token` → 200; `git ls-remote` with `x-bitbucket-api-token-auth:token` → OK.)

### Fix (recommended — small, future-proof)
In `src/clients/bitbucket.rs`, make `clone_username()` return
`x-bitbucket-api-token-auth` **when `self.username` looks like an Atlassian API token**
(heuristic: contains `@`, i.e. it's an email). Keep `self.username` for the REST client
(Basic auth) unchanged.
- App Passwords (plain `username:app_password`) and Bitbucket Access Tokens
  (`x-token-auth:token`) already use ONE username for both transports → leave them
  unaffected (no `@` → `clone_username()` returns `self.username` as today).
- The clone path (`src/services/repo.rs`) already calls `provider.clone_username()`,
  so only that one method changes; REST is untouched.

### Verify after the fix
- `git ls-remote https://x-bitbucket-api-token-auth:<token>@bitbucket.org/<ws>/<repo>.git` → lists refs.
- REST still 200 with the email username.
- End-to-end: open/update a Bitbucket PR on a repo whose webhook points at
  `…/webhook/bitbucket` → bugbot clones + reviews.

### No-code alternative
Use a Bitbucket **App Password** instead (one `username:app_password` works for both
transports). Downside: Atlassian is deprecating App Passwords.

### Deploy note
Code-only change → tag a release → Watchtower auto-deploys. No GitHub/Bitbucket
permission change. The VM `.env` already has the API token + email username set;
webhooks are per-repo (no workspace admin available).

---

## 2. GitHub Check Run (show in the PR "checks" list + optional merge gate)

### Why
bugbot posts **comments** only — it does NOT create a GitHub **Check Run**, so it never
appears in the PR "checks" list (Cursor BugBot does, because it uses the Checks API). A
check run also lets the review gate merges.

### Feature
- Add `create_check_run` (+ optional update) to `src/clients/github.rs`:
  `POST /repos/{owner}/{repo}/check-runs` with `name` (e.g. `himari-ai review`),
  `head_sha` (the PR head commit — already fetched as `head_commit` in `review.rs`),
  `status`/`conclusion`, and `output` (title + summary built from the review).
- Wire into the GitHub path of `review.rs` (after posting comments): create the check
  run with a conclusion derived from the findings.
- **Wire up the existing dangling gate config:** `BUGBOT_FAIL_ON_SEVERITY`
  (`config.rs`, default `critical`) is parsed but currently used ONLY by the CLI `scan`
  command — NOT in the webhook review path. Use it here: `conclusion = failure` if the
  top finding severity ≥ `fail_on_severity`, else `success` (or `neutral` when no
  findings). Mark the check as a required status check in branch protection to block
  merge.
- Bitbucket has no Checks API equivalent → guard on provider kind (GitHub-only).
- Optional UX: post an `in_progress` check at review start, flip to `completed` at the end.

### Permission change (GitHub App)
Add **Checks: Read & write** to the App's repository permissions. After saving, GitHub
requires re-accepting the new permission on each installation (approve in the
installation settings).

---

## Build / release conventions (see `CLAUDE.md`)
- Gate: `cargo fmt --all --check` · `cargo clippy --all-targets --all-features --locked -- -D warnings`
  · `cargo test --workspace --all-features --locked` · `cargo +1.88 check --workspace --locked` (MSRV 1.88).
- Release: bump `version` in `Cargo.toml`, merge to green `main`, push tag `vX.Y.Z` →
  `.github/workflows/release.yml` (version-guard → gate → build+push GHCR `:X.Y.Z`+`:latest`)
  → Watchtower on the VM auto-pulls `:latest`.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Suggestion
Both are independent, small changes — can ship together as one release (e.g. v0.4.2),
or Checks alone as v0.5.0 (since it adds a feature + an App permission).
