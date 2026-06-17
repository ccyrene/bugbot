//! bugbot — self-hosted AI PR reviewer (Rust).
//!
//! Module layout mirrors the original Python package:
//!   - `config`        env-driven settings
//!   - `error`         shared error types
//!   - `prompts`       embedded prompt templates + focus loader
//!   - `libs`          redact + logging
//!   - `services`      diff parser, secret scanner, git clone sandbox
//!   - `clients`       provider trait/models, bitbucket, github, llm backends
//!   - `review`        the orchestrator
//!   - `interactive`   GitHub conversational replies + commands + fixes
//!   - `server`        axum app, auth, webhook parsers, worker pool

pub mod clients;
pub mod config;
pub mod interactive;
pub mod libs;
pub mod prompts;
pub mod review;
pub mod server;
pub mod services;
