# Handoff: Convert bugbot's GitHub integration from PAT → GitHub App

**Date:** 2026-06-17 · **Branch:** `feat/github-app-auth` · **Base:** `main` @ `9918f77`

> Goal: make bugbot installable as a **GitHub App** (Cursor-BugBot–style) so it has
> its own `bugbot[bot]` identity, a single app-level webhook, and short-lived
> auto-rotating installation tokens — instead of the current static Personal
> Access Token (PAT). **Bitbucket stays on the app-password + webhook model**
> (Bitbucket Cloud has no equivalent install-app flow). The LLM backend
> (codex/claude) is a separate layer and is **not** touched by this work.

---

## 0. Do I need a separate GitHub account for the bot?

**No.** A GitHub App gets its own identity (`<app-slug>[bot]`) automatically. You
create the App under your existing personal account or org
(Settings → Developer settings → GitHub Apps → New). Its comments appear as the
`[bot]`, not as you. (Only the *PAT* model would want a dedicated machine-user
account so comments don't appear as yourself.)

---

## 1. Current state (verified in code, 2026-06-17)

bugbot authenticates to GitHub with a **static Bearer token** — no App auth exists.

| Concern | Where | Note |
|---|---|---|
| Auth header | `src/clients/github.rs:76` | `Authorization: Bearer {token}` — static |
| Client ctor | `src/clients/github.rs:66` | `GitHubClient::new(token, owner, repo, base_url, timeout)` |
| Token stored | `src/clients/github.rs:62,93` | `token: String` field; also used for git clone |
| Clone auth | `src/clients/github.rs:106-111` | `clone_username()="x-access-token"`, `clone_token()=&self.token` |
| Config | `src/config.rs:167-174` | `github_token: Option<Secret>`, `github_webhook_secret`, `github_bot_login` |
| Token read | `src/config.rs:273` | `env_secret(&["BUGBOT_GITHUB_TOKEN","GITHUB_TOKEN"])` |
| Client built | `src/server/worker.rs:173-185` | `build_github(s, owner, repo)` → reads `s.github_token` |
| Jobs | `src/server/worker.rs:21-33` | `ReviewJob{...,domain}` and `Job::Interact(GithubComment)` |
| Webhook handler | `src/server/app.rs` `handle_github` | HMAC verify already present; payload has `installation.id` |
| Bot identity (cosmetic) | `src/config.rs:174` | `github_bot_login` only used for reply-to-self detection |

There is **no** `app_id`, JWT, private-key, or installation-token logic anywhere
(grep confirms). HMAC webhook verification already works and is reusable as-is for
the App webhook secret.

---

## 2. GitHub App setup (in the GitHub UI — do this once)

1. **Settings → Developer settings → GitHub Apps → New GitHub App.**
2. **Webhook URL:** `https://<host>/webhook/github` · **Webhook secret:** the same
   value you put in `BUGBOT_GITHUB_WEBHOOK_SECRET` (`openssl rand -hex 32`).
3. **Repository permissions:**
   - **Contents:** Read & write (Read-only is fine if you never use `@bugbot fix`;
     write is needed for autofix push / branch creation).
   - **Pull requests:** Read & write.
   - **Metadata:** Read (implicit).
4. **Subscribe to events:** Pull request · Issue comment · Pull request review comment.
5. **Where can this app be installed:** "Only this account" (or "Any account" if public).
6. Generate a **private key** (`.pem`) — download it; this signs the JWT.
7. Note the **App ID** (numeric) shown on the App page.
8. **Install** the App on your account/org and select repos. Each installation has an
   **installation ID** (visible in the install URL or the webhook `installation.id`).

---

## 3. Code changes (implementation plan)

### 3a. Config — add App credentials (`src/config.rs`)
Add fields alongside the GitHub block (`config.rs:167`):
```rust
pub github_app_id: Option<String>,            // BUGBOT_GITHUB_APP_ID
pub github_app_private_key: Option<Secret>,   // BUGBOT_GITHUB_APP_PRIVATE_KEY (PEM)
// optional: pub github_app_private_key_path: Option<String>; // read PEM from file
```
Parse in `Settings::load` (near `config.rs:273`):
```rust
github_app_id: env_opt("BUGBOT_GITHUB_APP_ID"),
github_app_private_key: env_secret(&["BUGBOT_GITHUB_APP_PRIVATE_KEY"]),
```
Add a helper: `fn github_app_enabled(&self) -> bool { self.github_app_id.is_some() && self.github_app_private_key.is_some() }`.
Keep `github_token` as a **fallback** so PAT mode still works when the App isn't configured.

### 3b. New module — `src/clients/github_app.rs` (JWT → installation token)
Responsibilities:
- Build a **RS256 JWT** signed with the App private key. Claims: `iat = now-60`,
  `exp = now+600` (max 10 min), `iss = <app_id>`.
- `POST {base_url}/app/installations/{installation_id}/access_tokens` with
  `Authorization: Bearer {jwt}` → response `{ "token": "...", "expires_at": "..." }`.
- **Cache** the installation token per `installation_id` with its expiry; refresh when
  within ~5 min of expiry. Use `tokio::sync::Mutex<HashMap<u64, CachedToken>>`
  (mirror the `FixLimiter` pattern in `src/interactive.rs:27`).
- Suggested crate: **`jsonwebtoken`** (`EncodingKey::from_rsa_pem`, `Algorithm::RS256`).
  Stick with raw `reqwest` (already a dep) for the HTTP call — do **not** pull in
  `octocrab` (heavy; the codebase deliberately uses minimal deps).
- Use `std::time::SystemTime` for `iat`/`exp` (this is real app code — the
  `Date.now()` ban only applies to Workflow scripts, not the crate).

Sketch:
```rust
pub struct AppAuth { app_id: String, key: EncodingKey, http: Client, base_url: String,
                     cache: Mutex<HashMap<u64, (String /*token*/, i64 /*exp epoch*/)>> }
impl AppAuth {
    pub async fn installation_token(&self, installation_id: u64) -> Result<String> { /* cache+mint */ }
    fn app_jwt(&self) -> Result<String> { /* RS256, iss=app_id, iat/exp */ }
}
```

### 3c. Thread `installation_id` from webhook → Job (mirror the `domain` plumbing)
The webhook payload carries `installation.id`. Plumb it through exactly like the
`domain` field was added (see commit `e04a4d2` for the pattern):
- `src/server/webhook_github.rs`: add `installation_id: Option<u64>` to `GithubComment`
  (and parse `payload["installation"]["id"]`).
- `src/server/worker.rs`: add `installation_id: Option<u64>` to `ReviewJob` (`worker.rs:21`).
- `src/server/app.rs handle_github`: set `installation_id` on the job/comment before
  `worker.submit(...)` (same spot where `comment.domain = domain.clone()` is set).
- Fallback if absent: `GET /repos/{owner}/{repo}/installation` (with the App JWT)
  returns the installation for that repo → its `id`.

### 3d. Token provider in the client (`src/clients/github.rs` + `worker.rs:173`)
Two options (B is cleaner):
- **(A) Minimal:** mint the installation token in `build_github` and pass it to the
  existing `GitHubClient::new` (token stays a `String`). Simple, but the token can
  expire mid-run on long jobs.
- **(B) Robust:** give `GitHubClient` an enum token source
  `{ Static(String), App(Arc<AppAuth>, u64 /*installation_id*/) }` and resolve a fresh
  token per request (or per client build). Refreshes transparently.

`build_github(s, owner, repo, installation_id)` becomes:
```rust
if s.github_app_enabled() {
    let tok = app_auth.installation_token(installation_id?).await?;  // mint/cache
    GitHubClient::new(&tok, owner, repo, &s.github_base_url, s.github_timeout_seconds)
} else {
    // existing PAT path (worker.rs:174-185)
}
```
Note `build_github` is currently **sync**; it'll need to become `async` (callers at
`worker.rs:141,165` are already in async fns). `AppAuth` should be built once and shared
(put it in the worker/app state, like the shared `FixLimiter`).

### 3e. Git clone still works
`clone_token()` (`github.rs:109`) returns the bearer token. Installation tokens work as
the `x-access-token` git password for repos the App is installed on — no change needed
beyond passing the installation token instead of the PAT.

### 3f. Bot identity
Set `github_bot_login` to `<app-slug>[bot]` (or auto-detect once) so reply-to-self
detection (`src/interactive.rs:140`) recognizes the App's own comments.

---

## 4. Env vars (add to `deploy/.env.example` + README table)
```
BUGBOT_GITHUB_APP_ID=123456
BUGBOT_GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
# or mount the .pem and read a path (cleaner for Docker):
# BUGBOT_GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github_app.pem
BUGBOT_GITHUB_WEBHOOK_SECRET=<openssl rand -hex 32>   # already exists
# BUGBOT_GITHUB_TOKEN can be left unset when the App is configured.
```
For Docker: bind-mount the `.pem` read-only (e.g. `./github_app.pem:/run/secrets/github_app.pem:ro`)
and use `_PATH`, rather than stuffing a multiline PEM into an env var.

---

## 5. Testing
- **Unit:** `app_jwt()` produces a decodable RS256 JWT with correct `iss`/`exp`
  (sign with a throwaway test RSA key; verify with the public key).
- **Integration (wiremock):** mock `POST /app/installations/{id}/access_tokens` →
  assert the client uses the returned token as `Bearer` on a subsequent call, and that
  a cached token is reused before expiry. Follow the existing pattern in
  `tests/server_test.rs` / `src/clients/llm/codex.rs` tests.
- **Live smoke:** install the App on one test repo, open a PR, confirm a `bugbot[bot]`
  review appears; comment `@bugbot review` and `@bugbot fix` to exercise both token
  scopes.

---

## 6. Acceptance criteria
- [ ] App configured → reviews/replies/fixes post as `bugbot[bot]` using installation tokens.
- [ ] Installation token cached + auto-refreshed (no per-request mint storm; no mid-run expiry).
- [ ] PAT mode still works when the App env vars are unset (backward compatible).
- [ ] Bitbucket flow unchanged.
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` green
      (the CI gate in `.github/workflows/ci.yml` enforces this on the PR to `main`).

---

## 7. Deployment context (already done, 2026-06-17)
- VM: OVH `ubuntu@51.79.250.215`, Ubuntu 26.04, 2 vCPU / 3.7G RAM (+4G swap added), 36G disk.
- Installed: Docker 29.5.3 + Compose v5.1.4, Node 22, codex-cli 0.140.0, claude 2.1.179.
- Auth on VM: **codex + claude both authenticated** (creds copied from the dev box into
  `~/.codex/auth.json` and `~/.claude/.credentials.json`; verified working).
- Repo synced to `~/bugbot` on the VM (was deploying via Docker Compose; paused here to
  build the App feature first).
- Outstanding deploy decisions (for when you resume): TLS hostname (sslip.io
  `51.79.250.215.sslip.io` is the no-domain option), `BUGBOT_MAX_CONCURRENT_REVIEWS=1`
  for this 3.7G box, and the container-uid vs bind-mount-owner detail
  (container runs uid 10001; `~/.codex`/`~/.claude` are owned by uid 1000 — set
  compose `user:` or relax perms so the container can read them).

---

## 8. References
- Authenticating as a GitHub App installation: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
- Generating a JWT for a GitHub App: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
- Installation access tokens: `POST /app/installations/{installation_id}/access_tokens`
- `jsonwebtoken` crate: https://docs.rs/jsonwebtoken

**Estimated effort:** ~200–400 LOC (new `github_app.rs` + config + job plumbing + client
token source + tests). The `installation_id` plumbing mirrors the `domain` field added in
commit `e04a4d2` — use that as the worked example.
