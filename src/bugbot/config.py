from enum import Enum
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ClaudeEffort = Literal["low", "medium", "high", "xhigh", "max"]


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BUGBOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Claude Code CLI ------------------------------------------------
    claude_cli_path: str = "claude"
    claude_model: str = "sonnet"
    # `--effort` controls how much reasoning Claude does. `high` is a good
    # default for a code-review bot (worth the extra tokens). Allowed:
    # low | medium | high | xhigh | max.
    claude_effort: ClaudeEffort = "high"
    claude_timeout_seconds: float = 600.0
    # Read-only tools we let the model use inside the cloned working tree.
    # Comma-separated. Never include Bash/Edit/Write here.
    claude_allowed_tools: str = "Read,Grep,Glob"

    # ---- Bitbucket Cloud ------------------------------------------------
    # Default to the literal "x-token-auth" — the right value for Bitbucket
    # Repository / Workspace Access Tokens. Override only if you're using
    # an App Password (then this is your Bitbucket username).
    bitbucket_username: str = "x-token-auth"
    # Accept either `BUGBOT_BITBUCKET_APP_PASSWORD` (canonical) or the
    # shorter `BITBUCKET_TOKEN` for users who already store their PAT under
    # that name in CI / DO envs.
    bitbucket_app_password: SecretStr = Field(
        validation_alias=AliasChoices(
            "BUGBOT_BITBUCKET_APP_PASSWORD",
            "BITBUCKET_TOKEN",
        ),
    )
    bitbucket_base_url: str = "https://api.bitbucket.org/2.0"
    bitbucket_timeout_seconds: float = 60.0

    # ---- git clone ------------------------------------------------------
    git_clone_depth: int = Field(default=50, ge=1)
    git_clone_max_mb: int = Field(default=512, ge=16)
    git_clone_timeout_seconds: float = 180.0

    # ---- Webhook server -------------------------------------------------
    server_host: str = "0.0.0.0"
    server_port: int = 8080
    webhook_path: str = "/webhook/bitbucket"
    # Shared secret you configure when creating the Bitbucket webhook.
    # Required: we reject any unsigned/invalid request.
    webhook_secret: SecretStr
    # If true, validate the source IP against Atlassian's published ranges.
    webhook_enforce_ip_allowlist: bool = True
    # Refresh the IP ranges cache every N seconds.
    webhook_ip_cache_seconds: int = 3600
    # Trust X-Forwarded-For (set true only if running behind a reverse proxy
    # you control).
    trust_forwarded_for: bool = False
    # Hard-cap parallel review jobs; webhook returns 202 immediately and
    # processes in a background task.
    max_concurrent_reviews: int = Field(default=2, ge=1)

    # ---- Review behaviour ----------------------------------------------
    fail_on_severity: Severity = Severity.CRITICAL  # informational only in server mode
    max_inline_comments: int = Field(default=20, ge=0)
    max_diff_chars: int = Field(default=120_000, ge=1_000)
    ignore_globs: str = "*.lock,*.min.js,*.map,vendor/**,node_modules/**,dist/**,build/**"
    dry_run: bool = False

    bot_marker: str = "<!-- bugbot:v1 -->"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @property
    def ignore_glob_list(self) -> list[str]:
        return [p.strip() for p in self.ignore_globs.split(",") if p.strip()]

    @property
    def claude_allowed_tools_list(self) -> list[str]:
        return [t.strip() for t in self.claude_allowed_tools.split(",") if t.strip()]


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
