#!/usr/bin/env bash
# =====================================================================
# scripts/install-host.sh
#
# Bootstrap a Linux host (typically your DO droplet) to authenticate the
# Claude Code CLI against a Claude Pro/Max subscription, so the bugbot
# container can mount that auth at /home/bugbot/.claude:ro.
#
# You ONLY need this if you're using auth Path B (subscription).
# For Path A (ANTHROPIC_API_KEY), the Dockerfile installs claude inside
# the container — host install is not required.
#
# What it does:
#   1. Ensure Node.js (>= 20) is available, install via NodeSource if not.
#   2. npm install -g @anthropic-ai/claude-code
#   3. Run `claude login` interactively so you authenticate once.
#   4. Print the docker-compose bind-mount line to uncomment.
#
# Usage:
#   sudo bash scripts/install-host.sh         # interactive
#   curl ... | sudo bash                       # piped install (not recommended)
# =====================================================================

set -euo pipefail

NODE_MAJOR="${NODE_MAJOR:-20}"
CLAUDE_PKG="@anthropic-ai/claude-code"

log()  { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------
# 0. Sanity
# ---------------------------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
    die "this script targets Linux hosts (DO droplets, EC2, …). Got $(uname -s)."
fi

# We need root to install Node via apt + npm -g. Detect rather than insist
# on sudo so users running as root (e.g. in a brand-new droplet) also work.
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "must run as root or have sudo installed"
    SUDO="sudo"
fi

# ---------------------------------------------------------------------
# 1. Node.js
# ---------------------------------------------------------------------
need_node_install=false
if command -v node >/dev/null 2>&1; then
    cur="$(node -v | sed 's/^v//; s/\..*//')"
    if [[ "$cur" -lt "$NODE_MAJOR" ]]; then
        warn "node v$cur found, but we need >= v$NODE_MAJOR. Will upgrade."
        need_node_install=true
    else
        log "node v$cur present (>= v$NODE_MAJOR), keeping it."
    fi
else
    log "node not found, installing v$NODE_MAJOR.x via NodeSource."
    need_node_install=true
fi

if $need_node_install; then
    # Pin to NodeSource so we get a recent npm. The official Anthropic
    # instructions point at the same source.
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends ca-certificates curl gnupg
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | $SUDO -E bash -
    $SUDO apt-get install -y --no-install-recommends nodejs
fi

log "node:  $(node -v)"
log "npm:   $(npm -v)"

# ---------------------------------------------------------------------
# 2. Claude Code CLI
# ---------------------------------------------------------------------
if command -v claude >/dev/null 2>&1; then
    log "claude already installed: $(claude --version 2>/dev/null || echo unknown)"
    log "upgrading to latest"
fi
$SUDO npm install -g "$CLAUDE_PKG"
log "claude: $(claude --version)"

# ---------------------------------------------------------------------
# 3. Login (interactive)
# ---------------------------------------------------------------------
home_for_login="$HOME"
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    # When invoked via `sudo`, ~/.claude under root is the wrong target.
    # Prefer the invoking user's home so the mount path is predictable.
    home_for_login="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi

log "will write Claude auth to: $home_for_login/.claude/"
if [[ -d "$home_for_login/.claude" ]]; then
    warn "$home_for_login/.claude already exists — skipping `claude login`."
    warn "delete it and re-run if you want to re-authenticate."
else
    log "running \`claude login\` — follow the prompts"
    if [[ "$home_for_login" != "$HOME" ]]; then
        sudo -u "$SUDO_USER" -H claude login
    else
        claude login
    fi
fi

# ---------------------------------------------------------------------
# 4. Final instructions
# ---------------------------------------------------------------------
cat <<EOF

──────────────────────────────────────────────────────────────────────
✅  Host install complete.

To wire this into the bugbot container, edit deploy/docker-compose.yml:

    services:
      bugbot:
        volumes:
          - claude_state:/home/bugbot/.claude        # ← comment this out
          - $home_for_login/.claude:/home/bugbot/.claude:ro   # ← un-comment this

Then in deploy/.env, leave ANTHROPIC_API_KEY commented out (Path B uses
your subscription, not an API key).

Bring the stack up:

    cd deploy && docker compose up -d --build
──────────────────────────────────────────────────────────────────────
EOF
