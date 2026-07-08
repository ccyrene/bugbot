# CLAUDE.md — bugbot

Self-hosted AI PR reviewer for **GitHub + Bitbucket Cloud** (Rust). codex/claude CLI
backed, webhook-driven, with conversational GitHub interactivity.
Full docs: `README.md`. GitHub App auth design: `handoff.md`. Planned changes: `BACKLOG.md`.

## Build / test / lint (must pass — mirrors CI in `.github/workflows/ci.yml`)
- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- MSRV: `cargo +1.88 check --workspace --locked` (floor **1.88** — pulled up by
  jsonwebtoken → simple_asn1 → time 0.3.47)

## Conventions
- Third-party GitHub Actions pinned to full commit SHAs (supply-chain); Dependabot bumps them.
- Minimal deps by design: raw `reqwest`, enum dispatch (no `octocrab` / `async-trait` / `dyn`).
- Secrets: everything leaving the process goes through `libs::redact`; `config::Secret` masks `Debug`. Never log tokens / keys / PEMs.
- `main` is branch-protected: requires the aggregate `CI` check; merge via PR (review count 0, so CI-green is enough).
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Architecture — PR review flow
webhook (`server/app.rs`: provider-enabled → IP allowlist → HMAC over raw body → domain → parse)
→ bounded worker (`server/worker.rs`: dedupe key + semaphore, 202 immediately)
→ `review.rs` orchestrator: get PR+diff → parse diff → secret scan (`services/security.rs`)
→ clone + scrub injection files (`services/repo.rs`) → build prompt → LLM Review mode (strict JSON)
→ filter findings to added diff lines → dedupe → post summary + inline comments.
Auth: `clients/github_app.rs` (App installation tokens) or static PAT. Interactivity: `interactive.rs`.

## LLM backends (`clients/llm`)
`BUGBOT_LLM_BACKEND` (codex|claude) + optional `BUGBOT_LLM_FALLBACK_BACKEND`
→ `Failover` retries on any error **except timeout**. `@bugbot fix` needs codex
(claude path is read-only by design).

## Release / CD
Tag `v*` → `.github/workflows/release.yml`: version guard (tag MUST equal `Cargo.toml`
version) → fmt/clippy/test gate → build + push `ghcr.io/ccyrene/bugbot` (`:X.Y.Z` + `:latest`,
public). VM runs `deploy/docker-compose.prod.yml` (pulls the image) + a Watchtower sidecar
auto-pulls `:latest`. **Bump `Cargo.toml` version before tagging**, cut tags from green `main`.

## Production deploy
LIVE on OVH VM `ubuntu@51.79.250.215`. GitHub **App** `himari-ai[bot]` (App ID 4082955),
public endpoint `https://51.79.250.215.sslip.io`. `.env` at `~/bugbot/deploy/.env` (chmod 600).
codex/claude subscription auth in named volumes `deploy_codex_state` / `deploy_claude_state`
(chowned uid 10001 = container user). Changing `.env` requires recreating the container
(`docker compose -f docker-compose.prod.yml up -d bugbot`) — env is read at container create.

## Gotchas
- **claude auth headless:** copying a Claude Code subscription token from the host into
  the container 401s (OAuth doesn't transplant). Fix: set `CLAUDE_CONFIG_DIR=/home/bugbot/.claude`
  (so config persists in the mounted volume) and run `docker exec -it bugbot claude setup-token`
  **once** (long-lived token minted in-container). Codex subscription auth (`~/.codex`) works fine.
- GitHub App `issue_comment` webhook event only appears once the App has the **Issues**
  permission (R&W) — needed in addition to Contents + Pull requests.
- `containrrr/watchtower` is unmaintained re: new engines; needs `DOCKER_API_VERSION=1.40`
  on Docker Engine 25+ (its client defaults to API 1.25 → crash-loop otherwise).
- This `CLAUDE.md` (and `AGENTS.md` / `.cursorrules`) is **scrubbed from bugbot's review
  clones** as an anti-prompt-injection measure — it is dev/agent-facing only and never
  reaches the reviewer model.
