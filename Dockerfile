# =====================================================================
# bugbot — webhook server image (Rust rewrite)
#
# Multi-stage:
#   1. cargo-chef: cache the dependency compile
#   2. build the `bugbot` release binary
#   3. slim runtime with Node + the codex (+ claude) CLI + git
#
# Runs as non-root (uid 10001). tini is PID 1 to reap the Node grandchildren
# the codex/claude CLI spawns. Health check hits /healthz.
# =====================================================================

# --- 1. plan dependencies --------------------------------------------
FROM rust:1.97-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- 2. build --------------------------------------------------------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Compile deps only — cached unless Cargo.toml/lock change.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin bugbot

# --- 3. runtime ------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV NODE_MAJOR=22 \
    CODEX_HOME=/home/bugbot/.codex \
    DEBIAN_FRONTEND=noninteractive

# Node (for the codex/claude CLIs), git (clone + fix push), ca-certs, tini.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git tini gnupg \
 && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g @openai/codex @anthropic-ai/claude-code \
 && npm cache clean --force \
 && apt-get purge -y --auto-remove gnupg \
 && rm -rf /var/lib/apt/lists/* \
 && codex --version && claude --version

# Non-root runtime user with writable codex/claude auth dirs.
RUN useradd --create-home --shell /bin/bash --uid 10001 bugbot \
 && mkdir -p /home/bugbot/.codex /home/bugbot/.claude \
 && chown -R bugbot:bugbot /home/bugbot

COPY --from=builder /app/target/release/bugbot /usr/local/bin/bugbot

USER bugbot
WORKDIR /home/bugbot
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bugbot", "serve"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
