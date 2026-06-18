# Backlog

Planned changes captured for later. Bundle into a release.

_(empty — see Done below)_

## Done

### v0.4.1
- **Command triggers accept `@himari-ai` (bare slug) and `@bugbot`** — `parse_command`
  now matches `@bugbot`, `@<bot_login>` (e.g. `@himari-ai[bot]`), and the bare slug
  `@himari-ai` (bot_login with `[bot]` stripped). bugbot/Bitbucket + himari/GitHub.
- **Configurable log timezone** — `BUGBOT_LOG_UTC_OFFSET_HOURS` (default 0 = UTC);
  set to `7` for UTC+7. Implemented via fixed-offset `OffsetTime` in `libs/logging.rs`.
- **Comment attribution** — footer now shows the real model + token usage and drops
  the visible `· bugbot:v1` (kept as a hidden `<!-- bugbot:v1 -->` marker for
  idempotency).
