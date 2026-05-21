"""bugbot CLI.

Subcommands:
  serve       Start the webhook server (Bitbucket → review queue).
  review-pr   Run a one-off review against a specific PR (debug/backfill).
  scan        Run the secret scanner against a local diff file (no API
              calls) — handy as a pre-commit / pre-push hard gate.
  version     Print version.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from bugbot import __version__ as _pkg_version
from bugbot.clients._provider import PullRequestProvider
from bugbot.clients.bitbucket import BitbucketClient
from bugbot.clients.claude_cli import ClaudeCliClient
from bugbot.clients.github import GitHubClient
from bugbot.config import Severity, load_settings
from bugbot.libs.logging import configure_logging, get_logger
from bugbot.services.diff import parse_unified_diff
from bugbot.services.review import Reviewer, result_to_json
from bugbot.services.security import scan_diff

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="bugbot — Bitbucket/GitHub AI PR reviewer (Claude CLI backed)")
log = get_logger("cli")


@app.command()
def version() -> None:
    """Print the installed bugbot version."""
    typer.echo(_pkg_version)


@app.command()
def serve(
    host: Optional[str] = typer.Option(None, "--host", help="Override BUGBOT_SERVER_HOST."),
    port: Optional[int] = typer.Option(None, "--port", help="Override BUGBOT_SERVER_PORT."),
    workers: int = typer.Option(1, "--workers", help="uvicorn worker count."),
) -> None:
    """Start the FastAPI webhook server (`uvicorn`)."""
    settings = load_settings()
    configure_logging(settings.log_level)
    import uvicorn  # imported lazily so `scan` works without uvicorn installed

    uvicorn.run(
        "bugbot.server.app:create_app",
        factory=True,
        host=host or settings.server_host,
        port=port or settings.server_port,
        workers=workers,
        log_level=settings.log_level.lower(),
        access_log=True,
    )


@app.command("review-pr")
def review_pr(
    workspace: str = typer.Argument(..., help="Workspace (Bitbucket) or owner (GitHub)."),
    repo_slug: str = typer.Argument(..., help="Repository slug."),
    pr_id: int = typer.Argument(..., help="Pull request id."),
    provider: str = typer.Option(
        "bitbucket", "--provider", "-P",
        help="Which provider to review against: bitbucket or github.",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain",
        help="Focus domain (general / data-eng / asr). Defaults to BUGBOT_DEFAULT_DOMAIN.",
    ),
    artifact: Optional[Path] = typer.Option(
        None, "--artifact", help="If set, write the review JSON to this file."
    ),
) -> None:
    """Run a one-off review (debug / manual re-review)."""
    settings = load_settings()
    configure_logging(settings.log_level)
    log.info("manual review: {}:{}/{}#{}", provider, workspace, repo_slug, pr_id)

    provider_norm = provider.strip().lower()
    if provider_norm not in {"bitbucket", "github"}:
        raise typer.BadParameter(
            f"--provider must be 'bitbucket' or 'github', got {provider!r}"
        )

    client: PullRequestProvider
    if provider_norm == "bitbucket":
        if settings.bitbucket_app_password is None:
            raise typer.BadParameter(
                "Bitbucket is not configured — set BUGBOT_BITBUCKET_APP_PASSWORD "
                "(or BITBUCKET_TOKEN)."
            )
        client = BitbucketClient(
            username=settings.bitbucket_username,
            app_password=settings.bitbucket_app_password.get_secret_value(),
            workspace=workspace,
            repo_slug=repo_slug,
            base_url=settings.bitbucket_base_url,
            timeout=settings.bitbucket_timeout_seconds,
        )
    else:
        if settings.github_token is None:
            raise typer.BadParameter(
                "GitHub is not configured — set BUGBOT_GITHUB_TOKEN."
            )
        client = GitHubClient(
            token=settings.github_token.get_secret_value(),
            owner=workspace,
            repo=repo_slug,
            base_url=settings.github_base_url,
            timeout=settings.github_timeout_seconds,
        )

    claude = ClaudeCliClient(
        cli_path=settings.claude_cli_path,
        model=settings.claude_model,
        timeout=settings.claude_timeout_seconds,
    )
    with client, claude:  # type: ignore[arg-type]
        result = Reviewer(settings, provider=client, claude=claude).run(
            pr_id, domain=domain,
        )

    payload = result_to_json(result)
    if artifact:
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(payload, encoding="utf-8")
        log.info("wrote review artefact -> {}", artifact)


@app.command()
def scan(
    diff_path: Path = typer.Argument(..., exists=True, readable=True,
                                     help="Path to a unified-diff file"),
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on",
        help="Exit non-zero if any finding meets this severity.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", help="Write findings JSON to this file.",
    ),
) -> None:
    """Run the secret scanner against a local diff. No network calls."""
    configure_logging("INFO")
    files = parse_unified_diff(diff_path.read_text(encoding="utf-8"))
    findings = scan_diff(files)

    payload = {
        "findings": [
            {
                "file": f.file,
                "line": f.line,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "snippet": f.snippet,
            }
            for f in findings
        ],
    }
    text = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    typer.echo(text)

    top = Severity.NONE
    for f in findings:
        if f.severity.rank > top.rank:
            top = f.severity

    if fail_on != Severity.NONE and top.rank >= fail_on.rank:
        log.error("Secret scanner failed: top severity '{}' >= '{}'",
                  top.value, fail_on.value)
        sys.exit(2)


if __name__ == "__main__":
    app()
