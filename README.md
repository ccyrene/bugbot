# bugbot

**Self-hosted AI PR reviewer for Bitbucket Cloud *and* GitHub — Claude Code CLI backed, webhook-driven, deployable to any VPS.**

Cursor's bugbot doesn't speak Bitbucket. This one speaks both Bitbucket
Cloud and GitHub. It runs as a small FastAPI webhook server (e.g. on a
Digital Ocean droplet), listens to PR events from either forge, **clones
the PR branch into a sandboxed working tree**, and shells out to the
`claude` CLI which inspects the full repo via read-only tools (`Read`,
`Grep`, `Glob`) before posting inline + summary review comments. A
pre-LLM secret scanner blocks credentials from ever reaching the model.

You can enable either provider or both at the same time — each one has
its own webhook endpoint, IP allowlist, and HMAC secret.

---

## How it works

```
┌─────────────────────┐  webhook   ┌────────────────────────────────────┐
│  Bitbucket Cloud /  │ ─────────▶ │  Caddy (auto-TLS, path allowlist)  │
│  GitHub PR events   │            └────────────────┬───────────────────┘
└─────────────────────┘                             │
                                                    ▼
                              ┌─────────────────────────────────────────┐
                              │  bugbot (FastAPI, :8080, in Docker)     │
                              │                                         │
                              │  1. verify HMAC sig + IP allowlist      │
                              │  2. parse PR event → enqueue            │
                              │  3. return 202 (≈ms)                    │
                              │                                         │
                              │  ┌─────────────────────────────────┐    │
                              │  │  worker pool (N threads)        │    │
                              │  │   • fetch PR + diff (Bitbucket) │    │
                              │  │   • run secret scanner          │    │
                              │  │   • git clone source branch     │    │
                              │  │     into /tmp (size-capped)     │    │
                              │  │   • redact diff                 │    │
                              │  │   • subprocess: claude -p       │    │
                              │  │     • cwd = clone dir           │    │
                              │  │     • tools: Read,Grep,Glob     │    │
                              │  │       (read-only by design)     │    │
                              │  │   • parse JSON findings         │    │
                              │  │   • POST inline + summary       │    │
                              │  │   • rm -rf clone dir            │    │
                              │  └─────────────────────────────────┘    │
                              └─────────────────────────────────────────┘
```

A review takes a couple of minutes; Bitbucket's webhook deadline is ~10s
— so we **always 202 fast** and run the heavy work in a background worker
thread. Same PR re-fired (e.g. push update during a running review) is
**deduped** by `(workspace, repo, pr_id)`.

### What the LLM actually sees

| Source | Mechanism |
|---|---|
| PR title, author, branch names, description | in the user prompt |
| Pre-scan security findings (masked) | in the user prompt |
| Unified diff (truncated to `BUGBOT_MAX_DIFF_CHARS`, secrets redacted) | in the user prompt |
| **Full content of any file in the PR's source branch** | via `Read` tool on the cloned working tree |
| **Search across the whole repo** | via `Grep` / `Glob` tools |

The model is instructed to **default to the diff** and use tools only when
a finding cannot be verified from the diff alone — so review cost stays
bounded.

---

## Quickstart — Digital Ocean droplet

```bash
# 1. On the droplet (Ubuntu 22.04+, 2 GB RAM recommended):
curl -fsSL https://get.docker.com | sh
sudo apt-get install -y docker-compose-plugin

# 2. Get the code.
git clone <your-fork-url> bugbot && cd bugbot/deploy

# 3. Configure.
cp .env.example .env                 && $EDITOR .env
cp Caddyfile.example Caddyfile       && $EDITOR Caddyfile

# 4. (Auth path B only) authenticate the host's Claude subscription:
#    sudo bash ../scripts/install-host.sh
#    (installs Node + claude CLI, runs `claude login`, prints the
#    docker-compose bind-mount line to uncomment)

# 5. Bring it up.
docker compose up -d --build
docker compose logs -f bugbot caddy

# 6a. Register the Bitbucket webhook (per repo):
#       URL:     https://bugbot.yourdomain.com/webhook/bitbucket
#       Secret:  same value as BUGBOT_WEBHOOK_SECRET in .env
#       Trigger: Pull request → Created and Updated
#
# 6b. Register the GitHub webhook (per repo or per org):
#       Settings → Webhooks → Add webhook
#       Payload URL:  https://bugbot.yourdomain.com/webhook/github
#       Content type: application/json
#       Secret:       same value as BUGBOT_GITHUB_WEBHOOK_SECRET in .env
#       Events:       "Let me select individual events" → Pull requests
```

### Setting up GitHub support

1. Create a **Fine-grained Personal Access Token** at
   <https://github.com/settings/tokens?type=beta>. Repository access:
   pick the repos you want bugbot to review. Required permissions:

   - **Contents**: Read-only
   - **Pull requests**: Read & write
   - **Metadata**: Read-only (auto-included)

   Set `BUGBOT_GITHUB_TOKEN` (or `GITHUB_TOKEN`) in `.env`. The token
   serves both the REST API (Bearer auth) and `git clone` over HTTPS
   (`https://x-access-token:<token>@github.com/...`).

2. Generate a webhook secret: `openssl rand -hex 32`. Save it as
   `BUGBOT_GITHUB_WEBHOOK_SECRET`.

3. On each repo (or, for an org, **Settings → Webhooks** at the org
   level) add a webhook:

   | Field | Value |
   |---|---|
   | Payload URL | `https://<yourdomain>/webhook/github` |
   | Content type | `application/json` |
   | Secret | the value of `BUGBOT_GITHUB_WEBHOOK_SECRET` |
   | SSL verification | enabled |
   | Events | Pull requests only |
   | Active | ✔ |

4. `docker compose restart bugbot` to pick up the new env vars. Hitting
   "Recent Deliveries → Redeliver" in GitHub is the fastest way to
   verify the wiring.

Bitbucket-only or GitHub-only deployments are fine: the unconfigured
endpoint replies `503 — not configured` rather than silently accepting
unsigned traffic.

### Claude CLI auth — two paths, pick one

| | A. API key | B. Subscription |
|---|---|---|
| What you set | `ANTHROPIC_API_KEY` in `.env` | Bind-mount `~/.claude/` from host into container |
| Billing | Pay-per-token | Counts against Pro/Max plan |
| Setup | Easiest | Run `claude login` once on the host first |
| Container needs internet | yes | yes |

`bugbot` doesn't care which path you use — the `claude` CLI handles auth.

---

## CLI

```bash
bugbot serve                                            # start the webhook server
bugbot review-pr my-ws my-repo 42                       # Bitbucket (default)
bugbot review-pr acme widget 42 --provider github       # GitHub one-off review
bugbot scan pr.diff --fail-on high                      # offline secret scan, no LLM
bugbot version
```

Local development:

```bash
uv venv -p 3.12 .venv
.venv/bin/uv pip install -e ".[dev]"
cp deploy/.env.example .env && $EDITOR .env
.venv/bin/pytest -q                          # 85 tests
.venv/bin/bugbot serve --host 127.0.0.1
```

You'll need the Claude Code CLI installed (`npm i -g
@anthropic-ai/claude-code`) on your dev machine.

---

## Configuration

All settings live in `deploy/.env` (prefix `BUGBOT_`). See
[`deploy/.env.example`](deploy/.env.example) for the full set.

| Variable | Default | Required | Notes |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | — | A only | Set this XOR mount `~/.claude/` |

> `*` — at least one provider must be configured. The config validator
> refuses to start the server if no provider is set, or if an enabled
> provider is missing its webhook secret.
| `BUGBOT_CLAUDE_MODEL` | `sonnet` | | `sonnet`, `opus`, or full id |
| `BUGBOT_CLAUDE_TIMEOUT_SECONDS` | `600` | | Subprocess timeout |
| `BUGBOT_CLAUDE_ALLOWED_TOOLS` | `Read,Grep,Glob` | | Read-only by design. Bash/Edit/Write are refused at the client boundary |
| `BUGBOT_BITBUCKET_USERNAME` | `x-token-auth` | * | Owner of the app password / `x-token-auth` for Access Tokens |
| `BUGBOT_BITBUCKET_APP_PASSWORD` | — | * | repository:read, pullrequest:read/write (also accepts `BITBUCKET_TOKEN`) |
| `BUGBOT_GITHUB_TOKEN` | — | * | Fine-grained PAT — Contents: Read, Pull requests: Read & Write (also accepts `GITHUB_TOKEN`) |
| `BUGBOT_GITHUB_WEBHOOK_SECRET` | — | * | Required iff GitHub enabled. Match the secret you put in the GitHub webhook config |
| `BUGBOT_GITHUB_WEBHOOK_PATH` | `/webhook/github` | | URL path the GitHub webhook posts to |
| `BUGBOT_GIT_CLONE_DEPTH` | `50` | | Shallow-clone depth |
| `BUGBOT_GIT_CLONE_MAX_MB` | `512` | | Reject clones above this size |
| `BUGBOT_WEBHOOK_SECRET` | — | * | Required iff Bitbucket enabled. Match the Bitbucket webhook secret |
| `BUGBOT_WEBHOOK_ENFORCE_IP_ALLOWLIST` | `true` | | Verify against ip-ranges.atlassian.com + api.github.com/meta `hooks` |
| `BUGBOT_TRUST_FORWARDED_FOR` | `true` | | Caddy sits in front; we trust it |
| `BUGBOT_MAX_CONCURRENT_REVIEWS` | `2` | | Each owns one clone + one CLI |
| `BUGBOT_MAX_INLINE_COMMENTS` | `20` | | Hard cap per review |
| `BUGBOT_MAX_DIFF_CHARS` | `120000` | | Diff truncated above this |
| `BUGBOT_IGNORE_GLOBS` | `*.lock,*.min.js,…` | | Comma-separated globs |
| `BUGBOT_DRY_RUN` | `false` | | Log comments instead of posting |
| `BUGBOT_LOG_LEVEL` | `INFO` | | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

---

## What gets reviewed

### 1. Secret / sensitive-data scanner (no LLM, runs first)

Regex + entropy scan against the **added lines only** of the PR diff.
Findings are posted as **mandatory** inline comments — they can't be
suppressed by the model. Default rules:

| Category | Examples | Severity |
|---|---|---|
| Cloud keys | `AKIA…`, GCP `service_account` JSON | critical |
| Private keys | `-----BEGIN … PRIVATE KEY-----` | critical |
| LLM provider keys | OpenAI `sk-…`, `sk-ant-…`, `sk-or-v1-…` | critical |
| DB URIs with creds | `postgres://user:pw@host`, mysql, mongodb, redis | critical |
| VCS / CI tokens | `ghp_…`, `glpat-…`, GitHub fine-grained PAT | high |
| Chat hooks | Slack tokens & webhooks, Discord, Telegram bot | high |
| Generic | `password="…"`, `api_key="…"` (entropy + placeholder filter) | high |
| Basic-auth URLs | `https://user:pw@host` | high |
| JWTs | `eyJ…` (three-segment) | medium |
| Private IPv4 | `10.*`, `192.168.*`, `172.16-31.*` | low |

A placeholder denylist (`your-`, `xxxx`, `changeme`, `<TOKEN>`…) keeps
template files from spamming reviews.

### 2. Claude-powered review (with repo context)

After the secret gate passes, the worker:

1. Clones the PR's source branch into `/tmp` (tmpfs, size-capped, deleted
   after the review even on errors).
2. Redacts the diff again (defence in depth).
3. Invokes `claude -p` with the clone as the working directory and the
   read-only tool whitelist (`Read`, `Grep`, `Glob`).

The system prompt instructs the model to look for, in priority order:

1. Sensitive data leaks the scanner missed.
2. Security bugs — SQLi, SSRF, missing authn/authz, path traversal,
   unsafe deserialisation, broken TLS, insecure crypto.
3. Correctness bugs — wrong conditions, nil-deref, race conditions,
   swallowed exceptions.
4. Data-loss / blast-radius risks — destructive migrations, missing
   transactions, unbounded fan-out.
5. Performance footguns — N+1, accidental O(n²), missing indexes.

Style / formatting / naming is **explicitly out of scope** — that's
what linters are for.

Findings are post-processed:

- Line numbers validated against the diff. Context-line picks snap to the
  nearest added line within 3 lines; far-away picks are dropped.
- File paths not in the diff are dropped (hallucinations).
- Duplicates collapsed.
- Output capped at `BUGBOT_MAX_INLINE_COMMENTS`.
- Re-running on the same PR doesn't double-post (`<!-- bugbot:v1 -->`
  marker keys idempotency).

---

## Security stance

This tool has read/write access to your repos, **clones untrusted PR code**
to disk, and runs a Claude session over that working tree. Concrete
commitments:

### Secrets

- **No diff reaches the model with secrets.** Pattern + entropy scanner
  runs first; every prompt also passes through `bugbot.libs.redact` as
  defence in depth (cloud keys, PEMs, DB URIs, password assignments,
  any `https://user:pass@…` URL).
- **No raw secret in PR comments.** Scanner findings show
  `xxx…yz (N chars)`. The model is told never to echo a credential.
- **Argv hygiene.** The user prompt — which contains the diff — is fed
  to the CLI over **stdin**, not argv (which is world-readable via
  `/proc/<pid>/cmdline`).

### Webhook

- **HMAC-SHA256** of the raw body (constant-time compare). Bitbucket
  signs in `X-Hub-Signature`; GitHub in `X-Hub-Signature-256`. **Each
  provider has its own secret** — we refuse to share keys across forges
  so a leak on one side doesn't grant access to the other's pipeline.
- **IP allowlist** refreshed every hour from
  [`ip-ranges.atlassian.com`](https://ip-ranges.atlassian.com/) (Bitbucket)
  and [`api.github.com/meta`](https://api.github.com/meta) (GitHub —
  `hooks` array). Fail-open exactly once if the first fetch fails;
  fail-closed thereafter.
- Both checks run **before** the body is parsed.

### Cloned PR code

- Cloned into a process-private `/tmp/bugbot-clone-*` directory on
  **tmpfs** (memory-backed; nothing persists across container restarts).
- Clone is **shallow** (`--depth 50 --single-branch --no-tags
  --filter=blob:limit=1m`) and **size-capped** (`BUGBOT_GIT_CLONE_MAX_MB`).
- `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/echo` — never prompts for
  credentials interactively.
- `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null` — the
  host's gitconfig (which can include `credential.helper`, hooks, …)
  never influences the clone.
- The clone directory is `rm -rf`'d in a `finally` block — even on
  exceptions, even on partial clones.

### Claude CLI permissions

- `--allowed-tools Read,Grep,Glob` — explicit whitelist.
- The client **refuses** to accept `Bash`, `Edit`, `Write`,
  `MultiEdit`, or `WebFetch` in the allow-list regardless of what
  config says. Config can be misedited; this guard is the last line of
  defence.

### Container hardening

- Non-root user (uid 10001).
- Read-only rootfs; tmpfs for `/tmp` only.
- `no-new-privileges: true`.
- CPU + memory caps in compose.
- Port 8080 is **not** published — only the Caddy container can reach it
  over the internal docker network.
- JSON log rotation (10 MB × 5).

### Network surface

- Outbound destinations:
  - `api.bitbucket.org` (REST) + `bitbucket.org` (git clone) — only when Bitbucket is enabled
  - `api.github.com` (REST) + `github.com` (git clone) — only when GitHub is enabled
  - `ip-ranges.atlassian.com` and/or `api.github.com/meta` (IP allowlist refresh)
  - The Claude API endpoint (via the CLI; talks to `api.anthropic.com`)
- No telemetry, no error reporting service, no auto-update.

If you find a security issue, please raise it privately rather than via
public PR.

---

## Project layout

```
bugbot/
├── src/bugbot/
│   ├── cli/main.py            typer CLI: `serve` / `review-pr` / `scan`
│   ├── server/
│   │   ├── app.py             FastAPI app (lifespan + factory)
│   │   ├── auth.py            HMAC verify + Atlassian & GitHub IP allowlists
│   │   ├── webhook.py         Bitbucket event parser → ReviewJob
│   │   ├── webhook_github.py  GitHub event parser → ReviewJob
│   │   └── worker.py          Bounded ThreadPoolExecutor + dedupe (per provider)
│   ├── clients/
│   │   ├── _provider.py       PullRequestProvider Protocol + shared models
│   │   ├── bitbucket.py       Bitbucket Cloud v2 API client
│   │   ├── github.py          GitHub REST v3 API client
│   │   └── claude_cli.py      `claude -p` adapter (cwd + tools)
│   ├── services/
│   │   ├── diff.py            Unified-diff parser
│   │   ├── security.py        Pattern + entropy secret scanner
│   │   ├── repo.py            Sandboxed shallow git clone
│   │   └── review.py          Orchestrator
│   ├── prompts/
│   │   ├── system.md          Reviewer persona, tool guidance, JSON contract
│   │   └── user.md            PR context template
│   ├── libs/
│   │   ├── logging.py
│   │   └── redact.py          Defence-in-depth secret masker
│   └── config.py              pydantic-settings: env-driven config
├── deploy/
│   ├── docker-compose.yml     Compose: caddy + bugbot, hardened
│   ├── .env.example           Full env reference
│   └── Caddyfile.example      TLS + path allowlist + hardening headers
├── Dockerfile                 Python + Node (claude CLI), non-root, tini
├── tests/                     pytest — 85 tests
├── pyproject.toml
└── README.md (this file)
```

---

## Operating notes

- **Latency:** Bitbucket retries webhook deliveries that don't 2xx within
  ~10s. The server returns 202 in milliseconds; the review runs in the
  background.
- **Concurrency:** each running review owns one clone + one `claude`
  subprocess. `BUGBOT_MAX_CONCURRENT_REVIEWS` (default 2) is the only
  knob you usually need. Bump it only if your droplet has the RAM —
  each clone can be up to `BUGBOT_GIT_CLONE_MAX_MB`.
- **Cost:** roughly one Claude session per `pullrequest:created` and
  one per `pullrequest:updated`. Tool calls inside the session count
  against the same conversation budget.
- **Logs:** stdout, structured via loguru. `docker compose logs -f`
  during incidents; rotated to 10 MB × 5 by compose.
- **Re-review:** `docker compose exec bugbot bugbot review-pr <ws>
  <repo> <pr>`.

---

## Roadmap

- [ ] Inline-comment reply mode (debate with the bot in-thread).
- [ ] Bitbucket Server / Data Center support.
- [ ] Pluggable scanner rules via YAML.
- [ ] Persistent Redis-backed queue (replace in-process worker pool).
- [ ] Optional Bash tool inside a per-review nsjail/firejail sandbox.

---

## License

MIT — see [LICENSE](LICENSE).
