# =====================================================================
# bugbot — webhook server image
#
# Contains:
#   * Python 3.12-slim
#   * Node.js + @anthropic-ai/claude-code  (the `claude` CLI)
#   * bugbot (installed as a package, runs `bugbot serve`)
#
# Runs as a non-root user. Health check hits /healthz.
# =====================================================================

# --- 1. Build stage: install claude-code + python deps in one image ---
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NODE_VERSION=20

# Node.js (for the Claude Code CLI). curl + git are also useful inside
# a review run (git not strictly needed today, but keeps debug ergonomic).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git tini \
 && curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI globally.
RUN npm install -g @anthropic-ai/claude-code \
 && npm cache clean --force \
 && claude --version

# --- 2. Install bugbot ------------------------------------------------
WORKDIR /app

# Copy metadata first for cache friendliness.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --upgrade pip \
 && pip install .

# --- 3. Non-root runtime ---------------------------------------------
RUN useradd --create-home --shell /bin/bash --uid 10001 bugbot \
 && mkdir -p /home/bugbot/.claude \
 && chown -R bugbot:bugbot /home/bugbot

USER bugbot
WORKDIR /home/bugbot

EXPOSE 8080

# tini → handles SIGTERM cleanly, reaps zombies (Claude CLI spawns a node process).
ENTRYPOINT ["/usr/bin/tini", "--"]
# `bugbot serve` invokes uvicorn with the factory pattern internally
# (--factory). Override with e.g. `docker run … bugbot review-pr …` for
# one-off manual reviews.
CMD ["bugbot", "serve"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status==200 else 1)"
