# bugbot

**Self-hosted AI PR reviewer for Bitbucket Cloud *and* GitHub — written in Rust, `codex exec` backed (Claude CLI optional), webhook-driven, with Cursor-BugBot-style GitHub interactivity.**

Cursor's BugBot doesn't speak Bitbucket — and it can't hold a conversation in
a PR thread. This one does both. It runs as a small async webhook server
(one static binary), listens to PR events from either forge, **clones the PR
branch into a sandboxed working tree**, and shells out to the **`codex exec`**
CLI (read-only) to produce inline + summary review comments. A pre-LLM secret
scanner blocks credentials from ever reaching the model.

On **GitHub** it goes further than Cursor BugBot: you can **reply to its
comments to ask follow-ups**, **`@bugbot review`** to re-run, and
**`@bugbot fix …`** to have it push a fix (a new branch + PR, or a commit to
the PR branch).

Enable either provider or both — each has its own webhook endpoint, IP
allowlist, and HMAC secret.

> **This is the Rust rewrite (v0.2).** The original Python implementation is
> preserved under [`legacy/`](legacy/) for reference.

---

## How it works

```
┌─────────────────────┐  webhook   ┌────────────────────────────────────┐
│  Bitbucket Cloud /  │ ─────────▶ │  Caddy (auto-TLS, path allowlist)  │
│  GitHub PR + comment│            └────────────────┬───────────────────┘
│  events             │                             │
└─────────────────────┘                             ▼
                            ┌─────────────────────────────────────────────┐
                            │  bugbot  (axum, :8080, in Docker)           │
                            │  1. IP allowlist + HMAC over raw body       │
                            │  2. parse event → enqueue → 202 (≈ms)       │
                            │                                             │
                            │  worker pool (Semaphore-bounded, deduped)   │
                            │   REVIEW (PR open/update):                  │
                            │    • fetch PR + diff   • secret scan        │
                            │    • git clone branch (tmpfs, capped)       │
                            │    • scrub AGENTS.md/.cursor (injection)    │
                            │    • codex exec -s read-only --output-schema│
                            │    • validate findings → inline + summary   │
                            │   INTERACT (GitHub comments):               │
                            │    • @bugbot review / reply → Q&A in-thread │
                            │    • @bugbot fix → codex -s workspace-write │
                            │      → commit + push → open fix PR          │
                            └─────────────────────────────────────────────┘
```

A review takes a couple of minutes; the forge's webhook deadline is ~10s — so
we **always 202 fast** and run the heavy work on a bounded worker pool. The
same PR/comment re-fired is **deduped**.

### The LLM backend: `codex exec`

`codex exec` is the default. Key properties bugbot relies on (verified against
codex-cli 0.132.0):

| Concern | How |
|---|---|
| Secrets out of argv | prompt fed via **stdin** |
| Read-only review | `-s read-only` (model may read the tree; no writes, network off) |
| Strict findings JSON | `--output-schema <schema>` + `-o <file>` (no markdown-fence parsing) |
| **Prompt-injection from untrusted repos** | `-c project_doc_max_bytes=0` **and** the clone is scrubbed of `AGENTS.md`/`CLAUDE.md`/`.cursor` before the run |
| Hermetic | `--ephemeral --ignore-user-config --skip-git-repo-check` |
| Fix flow | `-s workspace-write` confines edits to the clone |

Set `BUGBOT_LLM_BACKEND=claude` to use the Claude Code CLI instead (read-only
review/Q&A; the `@bugbot fix` flow requires codex).

---

## GitHub interactivity

Subscribe the GitHub webhook to **Pull requests**, **Issue comments**, and
**Pull request review comments**. Then, on any PR:

| You type… | bugbot… |
|---|---|
| (PR opened / pushed) | reviews automatically |
| `@bugbot review` · `bugbot run` · `cursor review` | re-reviews on demand |
| reply to a bugbot comment, or `@bugbot <question>` | answers **in the same thread**, with the diff + repo as context |
| `@bugbot fix <instruction>` | runs codex in workspace-write mode, commits the change, and (default) opens a **fix PR** into your branch |
| `@bugbot help` | lists commands |

Loops are guarded: bugbot never replies to its own comments, and autofix is
capped at `BUGBOT_FIX_MAX_PER_PR_24H` per PR.

---

## Quickstart (Docker)

```bash
# On the host (2–8 GB RAM depending on load — see "Host sizing"):
curl -fsSL https://get.docker.com | sh
sudo apt-get install -y docker-compose-plugin

git clone <your-fork-url> bugbot && cd bugbot/deploy
cp .env.example .env           && $EDITOR .env
cp Caddyfile.example Caddyfile && $EDITOR Caddyfile   # set your hostname

# Subscription auth (optional): run `codex login` on the host, then
# uncomment the ~/.codex bind-mount in docker-compose.yml:
sudo bash ../scripts/install-host.sh

docker compose up -d --build
docker compose logs -f bugbot caddy
```

Register webhooks:

- **GitHub — option A: GitHub App** (preferred — own `[bot]` identity + short-lived
  auto-rotating installation tokens). **Settings → Developer settings → GitHub Apps → New**:
  - Webhook URL `https://<host>/webhook/github` (or `…/webhook/github/<domain>`),
    secret `BUGBOT_GITHUB_WEBHOOK_SECRET`
  - Repository permissions: **Contents: R&W**, **Pull requests: R&W**, Metadata: R
    (Contents *Read* is enough without `@bugbot fix`)
  - Subscribe to: **Pull request**, **Issue comment**, **Pull request review comment**
  - Generate a private key (`.pem`), note the **App ID**, then **install** it on your repos.
  - Set `BUGBOT_GITHUB_APP_ID`, `BUGBOT_GITHUB_APP_PRIVATE_KEY[_PATH]`, and
    `BUGBOT_GITHUB_BOT_LOGIN=<app-slug>[bot]`.
- **GitHub — option B: PAT** → repo/org **Settings → Webhooks → Add webhook**
  - Payload URL: `https://<host>/webhook/github` (or `…/webhook/github/<domain>`)
  - Content type: `application/json`, Secret: `BUGBOT_GITHUB_WEBHOOK_SECRET`
  - Events: **Pull requests**, **Issue comments**, **Pull request review comments**
  - Token (fine-grained PAT): **Contents: Read & write**, **Pull requests: Read & write**
    (Contents *Read* is enough if you don't use `@bugbot fix`.)
- **Bitbucket** → repo **Settings → Webhooks**
  - URL: `https://<host>/webhook/bitbucket`, Secret: `BUGBOT_WEBHOOK_SECRET`
  - Trigger: Pull request → Created and Updated

---

## Releases & continuous deployment

Pull-based CD: a tagged release builds an image, pushes it to GHCR, and the VM's
**Watchtower** sidecar pulls it automatically. No SSH key in CI, no inbound
access to the VM, no registry credentials (the image is public).

```
git tag v0.3.0 && git push origin v0.3.0
        │
        ▼  .github/workflows/release.yml
  version guard (tag == Cargo.toml)  →  gate (fmt/clippy/test)  →  build & push
        │
        ▼  ghcr.io/ccyrene/bugbot:0.3.0  +  :0.3  +  :sha-xxxx  +  :latest
        │
        ▼  Watchtower on the VM (polls every 5 min) pulls :latest → recreates bugbot
```

**Cut a release**

1. Bump `version` in `Cargo.toml` (and refresh `Cargo.lock`), merge to green `main`.
2. `git tag vX.Y.Z && git push origin vX.Y.Z` — the tag must equal the crate version
   or the workflow fails fast. (`vX.Y.Z-rc1` publishes `:X.Y.Z-rc1` but does **not**
   move `:latest`, so prereleases never auto-deploy.)
3. The `Release` workflow publishes to `ghcr.io/<owner>/<repo>`. **One-time:** after the
   first publish, set the GHCR package visibility to **Public** (repo → Packages → the
   package → Package settings → Change visibility) so the VM can pull without auth.

**Deploy target (VM)** — use the production compose, which pulls the image and runs
Watchtower instead of building locally:

```bash
cd deploy
cp .env.example .env           && $EDITOR .env
cp Caddyfile.example Caddyfile && $EDITOR Caddyfile
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs -f bugbot watchtower
```

Watchtower auto-updates only the `bugbot` container (it carries the
`com.centurylinklabs.watchtower.enable` label; `caddy` is left alone). Pin a version
to opt out of auto-tracking: `BUGBOT_IMAGE_TAG=0.3.0 docker compose -f
docker-compose.prod.yml up -d`. The plain `docker-compose.yml` remains the
local **build-from-source** path for development.

---

## Host sizing

The Rust server itself is tiny (~10–30 MB RSS, async). The cost is dominated by
the **Node-based codex/claude CLI** (≈500 MB RSS baseline per concurrent run,
with documented spikes) plus one **git clone** per job (capped at
`BUGBOT_GIT_CLONE_MAX_MB`, default 512 MB; lands in RAM when `/tmp` is tmpfs).

Budget **~1.5–2 GB RAM per concurrent review** (`BUGBOT_MAX_CONCURRENT_REVIEWS`)
and roughly **1 vCPU per concurrent review**.

| Tier | Use | vCPU | RAM | Disk | `MAX_CONCURRENT_REVIEWS` |
|---|---|---|---|---|---|
| **Light** | one repo, occasional PRs | 1–2 | **4 GB** (2 GB bare minimum) | 20 GB SSD | 1 |
| **Team** | a few active repos, bursts | 2–4 | **8 GB** | 40 GB SSD | 2–4 |
| **Heavy** | org-wide, many PRs + fixes | 4–8 | **16 GB+** | 80 GB SSD | 4–8 |

Notes:
- The old Python README suggested 2 GB — that's too tight for the conversational
  + autofix workload; 4 GB is the safer floor.
- Enforce a hard per-container memory cap (compose `deploy.resources.limits.memory`,
  set to 4g by default) so a CLI memory spike can't take down the box.
- Keep `/tmp` on tmpfs (compose does, `size=1g`) so untrusted clones never persist.
- A typical dev workstation (e.g. 14 cores / 8 GB) comfortably runs
  `MAX_CONCURRENT_REVIEWS=2–3`.

---

## CLI

```bash
bugbot serve                                   # start the webhook server
bugbot review-pr acme widget 42 --provider github   # one-off review
bugbot review-pr my-ws my-repo 42                    # Bitbucket (default)
bugbot review-pr acme widget 42 -P github --domain asr --artifact out.json
bugbot scan pr.diff --fail-on high             # offline secret scan, no LLM
bugbot version
```

---

## Configuration

All settings are env vars prefixed `BUGBOT_` (see
[`deploy/.env.example`](deploy/.env.example) for the annotated full set).

| Variable | Default | Notes |
|---|---|---|
| `BUGBOT_LLM_BACKEND` | `codex` | primary backend: `codex` or `claude` |
| `BUGBOT_LLM_FALLBACK_BACKEND` | — | failover backend on any non-timeout error (e.g. `claude` primary → `codex`); needs auth for both |
| `BUGBOT_CODEX_CLI_PATH` | `codex` | |
| `BUGBOT_CODEX_MODEL` | — | unset = codex default (e.g. gpt-5.5) |
| `BUGBOT_CODEX_REASONING_EFFORT` | — | `low`/`medium`/`high` |
| `BUGBOT_CODEX_TIMEOUT_SECONDS` | `900` | per-call hard timeout (codex has none of its own) |
| `OPENAI_API_KEY` | — | codex Path A (XOR mount `~/.codex`) |
| `BUGBOT_CLAUDE_MODEL` | `sonnet` | claude backend only |
| `ANTHROPIC_API_KEY` | — | claude Path A (XOR mount `~/.claude`) |
| `BUGBOT_BITBUCKET_APP_PASSWORD` | — | enables Bitbucket (alias `BITBUCKET_TOKEN`) |
| `BUGBOT_WEBHOOK_SECRET` | — | required iff Bitbucket enabled |
| `BUGBOT_GITHUB_APP_ID` | — | enables GitHub **App** auth (preferred); numeric App ID |
| `BUGBOT_GITHUB_APP_PRIVATE_KEY` | — | App private key PEM (or use `…_PATH`) |
| `BUGBOT_GITHUB_APP_PRIVATE_KEY_PATH` | — | path to the App `.pem` (takes precedence over inline) |
| `BUGBOT_GITHUB_TOKEN` | — | enables GitHub via PAT (fallback; alias `GITHUB_TOKEN`) |
| `BUGBOT_GITHUB_WEBHOOK_SECRET` | — | required iff GitHub enabled |
| `BUGBOT_GITHUB_BOT_LOGIN` | auto | login that counts as "us"; **required** for App+interactive (PAT: auto via `GET /user`) |
| `BUGBOT_INTERACTIVE_ENABLED` | `true` | handle comment events (Q&A + commands) |
| `BUGBOT_FIX_ENABLED` | `true` | allow `@bugbot fix` (needs codex + Contents:write) |
| `BUGBOT_FIX_MAX_PER_PR_24H` | `3` | autofix loop guard |
| `BUGBOT_FIX_BRANCH_STRATEGY` | `new-branch` | `new-branch` (opens a PR) or `existing-branch` |
| `BUGBOT_MAX_CONCURRENT_REVIEWS` | `2` | see Host sizing |
| `BUGBOT_MAX_INLINE_COMMENTS` | `20` | hard cap per review |
| `BUGBOT_MAX_DIFF_CHARS` | `120000` | diff truncated above this |
| `BUGBOT_GIT_CLONE_MAX_MB` | `512` | reject clones above this |
| `BUGBOT_WEBHOOK_ENFORCE_IP_ALLOWLIST` | `true` | Atlassian + GitHub `/meta` ranges |
| `BUGBOT_DRY_RUN` | `false` | log comments instead of posting |
| `BUGBOT_DEFAULT_DOMAIN` | `general` | focus when a bare webhook path is used |

At least one provider must be configured, and each enabled provider needs its
own webhook secret — the server refuses to start otherwise.

---

## Per-repo review focus

A data-eng pipeline and an ML training repo care about different things.
bugbot ships **focus prompts** selected via the webhook URL suffix:

```
https://<host>/webhook/github                → BUGBOT_DEFAULT_DOMAIN
https://<host>/webhook/github/data-eng       → data-eng focus
https://<host>/webhook/bitbucket/asr         → asr focus
```

| Domain | Prioritises |
|---|---|
| `general` | data leaks, security bugs (SQLi/SSRF/authn), correctness, data-loss, perf footguns |
| `data-eng` | pipeline correctness (DAG deps, idempotency, watermarks), schema/migration safety, query patterns |
| `asr` | ML/speech: train/val/test leakage (speaker overlap), reproducibility, training correctness, audio/feature bugs |

Add your own by dropping `prompts/focus/<name>.md`, adding it to the registry
in `src/prompts.rs`, and rebuilding. Unknown domains **400** at the webhook
layer (loud at delivery time).

---

## What gets reviewed

### 1. Secret scanner (no LLM, runs first)
Regex + entropy scan over the **added lines** only. HIGH/CRITICAL hits are
posted as **mandatory** comments (the model can't suppress them) and the raw
value is masked (`AKI…LE (20 chars)`) everywhere. Covers cloud keys, PEM
private keys, LLM-provider keys (OpenAI/Anthropic/OpenRouter), DB URIs with
creds, VCS/CI tokens, chat webhooks, JWTs, basic-auth URLs, private IPs.

### 2. codex-powered review (with repo context)
The model gets the PR metadata, masked scanner findings, the redacted diff, and
the full post-change content of changed files inlined; it may read other files
in the (read-only) clone for context. Findings are validated: line numbers
snapped to added lines (or dropped), hallucinated paths dropped, duplicates
collapsed, capped, and grouped per file. Style/formatting is out of scope.

---

## Security stance

- **No secret reaches the model**: pre-scan + a defence-in-depth redactor on
  every prompt; the prompt is fed over stdin, not argv.
- **Untrusted-code hardening**: clones are shallow, single-branch, size-capped,
  on tmpfs, `rm`'d on drop; git runs hermetically (`GIT_CONFIG_GLOBAL=/dev/null`,
  no askpass/prompt). codex runs `-s read-only` with network off. The clone is
  **scrubbed** of `AGENTS.md`/`AGENTS.override.md`/`CLAUDE.md`/`.cursor`/
  `.cursorrules`/`copilot-instructions.md` and codex runs with
  `project_doc_max_bytes=0` — closing the verified AGENTS.md prompt-injection
  vector.
- **Webhook**: HMAC-SHA256 over the raw body (constant-time), separate secret
  per forge, IP allowlist refreshed hourly (fail-open once, then fail-closed).
  Both run before the body is parsed.
- **Container**: non-root (uid 10001), tmpfs `/tmp`, `no-new-privileges`,
  memory cap, port 8080 unpublished (only Caddy reaches it).
- The `@bugbot fix` path is the one place bugbot **writes** — guarded by
  `BUGBOT_FIX_ENABLED`, a per-PR rate limit, and (default) isolation to a new
  branch + PR rather than committing to the PR branch directly.

---

## Project layout

```
bugbot/
├── src/
│   ├── main.rs            clap CLI: serve / review-pr / scan / version
│   ├── config.rs          env-driven Settings + Severity + Secret
│   ├── prompts.rs         embedded prompts + focus registry
│   ├── review.rs          the review orchestrator
│   ├── interactive.rs     GitHub Q&A + commands + fix flow
│   ├── libs/              redact, logging (tracing)
│   ├── services/          diff parser, secret scanner, git clone sandbox
│   ├── clients/
│   │   ├── provider.rs    PR models + enum-dispatch Provider
│   │   ├── bitbucket.rs   Bitbucket Cloud v2
│   │   ├── github.rs      GitHub REST v3 (+ interactive endpoints)
│   │   └── llm/           LlmBackend: codex.rs (default) + claude.rs
│   └── server/            axum app, auth (HMAC+IP), webhook parsers, worker
├── prompts/               system/user/reply/fix + focus/*.md
├── deploy/                docker-compose, Caddyfile, .env.example
├── Dockerfile             cargo-chef build + Node + codex/claude CLIs
├── tests/                 webhook integration tests
├── legacy/                the original Python implementation (reference)
└── Cargo.toml
```

## Building from source

```bash
cargo build --release        # → target/release/bugbot
cargo test                   # 60 tests
cargo clippy --all-targets
```

You'll need the `codex` CLI on PATH (`npm i -g @openai/codex`) — and `claude`
(`npm i -g @anthropic-ai/claude-code`) if you use that backend.

## License

MIT — see [LICENSE](LICENSE).
