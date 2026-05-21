from enum import Enum
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, model_validator
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
        # Allow kwargs to use the canonical field name even when the field
        # also has a `validation_alias` (the AliasChoices on bitbucket /
        # github tokens). Without this, `Settings(github_token=...)` would
        # be silently dropped because pydantic only checks aliases.
        populate_by_name=True,
    )

    # ---- Claude Code CLI ------------------------------------------------
    claude_cli_path: str = "claude"
    claude_model: str = "sonnet"
    # `--effort` controls how much reasoning Claude does. Allowed:
    # low | medium | high | xhigh | max. Leave None to omit the flag and
    # let the CLI use its default — **strongly recommended** at the
    # moment because `--effort` combined with `-p` is silently broken in
    # claude-code 2.1.x (process exits 0 with empty stdout). Set to a
    # non-None level once the CLI fix lands upstream.
    claude_effort: ClaudeEffort | None = None
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
    # shorter `BITBUCKET_TOKEN`. Optional — leave unset for GitHub-only
    # deployments. The `model_validator` below enforces "at least one
    # provider configured".
    bitbucket_app_password: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "BUGBOT_BITBUCKET_APP_PASSWORD",
            "BITBUCKET_TOKEN",
        ),
    )
    bitbucket_base_url: str = "https://api.bitbucket.org/2.0"
    bitbucket_timeout_seconds: float = 60.0

    # ---- GitHub ---------------------------------------------------------
    # Fine-grained or classic PAT. Required permissions on a fine-grained
    # PAT: Contents: Read, Pull requests: Read & Write. Optional — leave
    # unset for Bitbucket-only deployments.
    github_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "BUGBOT_GITHUB_TOKEN",
            "GITHUB_TOKEN",
        ),
    )
    # Separate webhook secret for GitHub — never share a secret between
    # providers. Optional only because GitHub is optional.
    github_webhook_secret: SecretStr | None = None
    github_base_url: str = "https://api.github.com"
    github_timeout_seconds: float = 60.0
    github_webhook_path: str = "/webhook/github"

    # ---- git clone ------------------------------------------------------
    git_clone_depth: int = Field(default=50, ge=1)
    git_clone_max_mb: int = Field(default=512, ge=16)
    git_clone_timeout_seconds: float = 180.0

    # ---- Webhook server -------------------------------------------------
    server_host: str = "0.0.0.0"
    server_port: int = 8080
    webhook_path: str = "/webhook/bitbucket"
    # Shared secret you configure when creating the Bitbucket webhook.
    # Required iff Bitbucket is enabled (paired with bitbucket_app_password);
    # see the model_validator below.
    webhook_secret: SecretStr | None = None
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
    # Total cap on inlined post-change file content in the prompt.
    # Each file is also individually capped at max_file_chars / 4.
    max_file_chars: int = Field(default=200_000, ge=1_000)
    ignore_globs: str = "*.lock,*.min.js,*.map,vendor/**,node_modules/**,dist/**,build/**"
    dry_run: bool = False

    # Substring stamped into every bot-posted comment for idempotency.
    # Bitbucket Cloud's comment renderer doesn't strip HTML comments, so we
    # use a plain code-friendly tag instead — gets rendered as `bugbot:v1`
    # via an inline code span in the comment template.
    bot_marker: str = "bugbot:v1"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @property
    def ignore_glob_list(self) -> list[str]:
        return [p.strip() for p in self.ignore_globs.split(",") if p.strip()]

    @property
    def claude_allowed_tools_list(self) -> list[str]:
        return [t.strip() for t in self.claude_allowed_tools.split(",") if t.strip()]

    @property
    def bitbucket_enabled(self) -> bool:
        return self.bitbucket_app_password is not None

    @property
    def github_enabled(self) -> bool:
        return self.github_token is not None

    @model_validator(mode="after")
    def _validate_providers(self) -> "Settings":
        # At least one provider must be configured — otherwise the server
        # has nothing to do.
        if not self.bitbucket_enabled and not self.github_enabled:
            raise ValueError(
                "No PR provider configured. Set BUGBOT_BITBUCKET_APP_PASSWORD "
                "(or BITBUCKET_TOKEN) and/or BUGBOT_GITHUB_TOKEN."
            )
        # Each enabled provider needs its own webhook secret. We refuse to
        # share secrets across providers — leaking one shouldn't grant
        # access to the other's pipeline.
        if self.bitbucket_enabled and self.webhook_secret is None:
            raise ValueError(
                "BUGBOT_WEBHOOK_SECRET is required when Bitbucket is enabled."
            )
        if self.github_enabled and self.github_webhook_secret is None:
            raise ValueError(
                "BUGBOT_GITHUB_WEBHOOK_SECRET is required when GitHub is enabled."
            )
        return self


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
