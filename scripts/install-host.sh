#!/usr/bin/env bash
# =====================================================================
# scripts/install-host.sh
#
# Bootstrap a Linux host to authenticate the codex CLI (and optionally the
# claude CLI) against a subscription, so the bugbot container can bind-mount
# that auth and use it instead of an API key.
#
# You ONLY need this for subscription auth (Path B). For API keys (Path A)
# set OPENAI_API_KEY / ANTHROPIC_API_KEY in deploy/.env instead.
#
# What it does:
#   1. Ensure Node.js (>= 20).
#   2. npm install -g @openai/codex  (and @anthropic-ai/claude-code if asked)
#   3. Run `codex login` interactively.
#   4. Print the docker-compose bind-mount line to uncomment.
#
# Usage:
#   sudo bash scripts/install-host.sh                 # codex only
#   WITH_CLAUDE=1 sudo bash scripts/install-host.sh   # also claude
# =====================================================================

set -euo pipefail

NODE_MAJOR="${NODE_MAJOR:-22}"
WITH_CLAUDE="${WITH_CLAUDE:-0}"

log()  { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "this script targets Linux hosts. Got $(uname -s)."

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "must run as root or have sudo installed"
    SUDO="sudo"
fi

# ---- Node.js --------------------------------------------------------
need_node=false
if command -v node >/dev/null 2>&1; then
    cur="$(node -v | sed 's/^v//; s/\..*//')"
    if [[ "$cur" -lt "$NODE_MAJOR" ]]; then warn "node v$cur < v$NODE_MAJOR, upgrading."; need_node=true
    else log "node v$cur present, keeping it."; fi
else
    log "node not found, installing v$NODE_MAJOR.x"; need_node=true
fi
if $need_node; then
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends ca-certificates curl gnupg
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | $SUDO -E bash -
    $SUDO apt-get install -y --no-install-recommends nodejs
fi
log "node: $(node -v)  npm: $(npm -v)"

# ---- CLIs -----------------------------------------------------------
$SUDO npm install -g @openai/codex
log "codex: $(codex --version 2>/dev/null || echo unknown)"
if [[ "$WITH_CLAUDE" == "1" ]]; then
    $SUDO npm install -g @anthropic-ai/claude-code
    log "claude: $(claude --version 2>/dev/null || echo unknown)"
fi

# ---- login (interactive) -------------------------------------------
home_for_login="$HOME"
run_as=""
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    home_for_login="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    run_as="sudo -u $SUDO_USER -H"
fi

if [[ -d "$home_for_login/.codex" ]]; then
    warn "$home_for_login/.codex already exists — skipping \`codex login\`. Delete it to re-auth."
else
    log "running \`codex login\` — follow the prompts"
    $run_as codex login
fi
if [[ "$WITH_CLAUDE" == "1" && ! -d "$home_for_login/.claude" ]]; then
    log "running \`claude login\`"
    $run_as claude login
fi

cat <<EOF

──────────────────────────────────────────────────────────────────────
✅  Host install complete.

In deploy/docker-compose.yml, uncomment the bind-mount(s) under the bugbot
service to use this host's subscription auth:

    volumes:
      - codex_state:/home/bugbot/.codex          # ← comment this out
      - $home_for_login/.codex:/home/bugbot/.codex   # ← un-comment this
EOF
if [[ "$WITH_CLAUDE" == "1" ]]; then
cat <<EOF
      - $home_for_login/.claude:/home/bugbot/.claude  # ← (claude backend)
EOF
fi
cat <<EOF

Leave OPENAI_API_KEY / ANTHROPIC_API_KEY commented out in deploy/.env
(Path B uses the subscription, not an API key).

    cd deploy && docker compose up -d --build
──────────────────────────────────────────────────────────────────────
EOF
