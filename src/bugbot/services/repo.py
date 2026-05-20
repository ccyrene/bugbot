"""Git clone helper for the PR branch.

We clone shallow into a process-private tmp dir. The credentials are
embedded in the URL only inside `subprocess.run` (never logged, never
persisted to `~/.git-credentials`). The clone is wrapped in a context
manager so the directory is reliably cleaned up even on exceptions.

What we clone:
  * `<source_branch>` (HEAD of the PR author's branch)
  * shallow (--depth=<settings.git_clone_depth>) — enough for diff
    context, far cheaper than full history
  * single-branch — no other branches pulled in

We do NOT run git hooks or apply git config from the cloned repo.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from bugbot.libs.logging import get_logger
from bugbot.libs.redact import redact

log = get_logger("repo")


class GitCloneError(RuntimeError):
    pass


@dataclass(frozen=True)
class ClonedRepo:
    path: Path
    workspace: str
    repo_slug: str
    branch: str
    head_commit: str


def _bitbucket_clone_url(*, workspace: str, repo_slug: str,
                        username: str, app_password: str) -> str:
    """Build an HTTPS URL with embedded basic-auth.

    URL-encode both username and password — usernames may contain `@`,
    passwords may contain `/` or `:`. Wrong encoding here = "remote not
    found" or auth header leak.
    """
    user = urllib.parse.quote(username, safe="")
    pw = urllib.parse.quote(app_password, safe="")
    return f"https://{user}:{pw}@bitbucket.org/{workspace}/{repo_slug}.git"


def _redact_url(cmd: list[str]) -> list[str]:
    out: list[str] = []
    for arg in cmd:
        if arg.startswith("https://") and "@" in arg:
            # Strip basic-auth before any logging.
            parsed = urllib.parse.urlparse(arg)
            out.append(f"{parsed.scheme}://***:***@{parsed.netloc.split('@', 1)[-1]}{parsed.path}")
        else:
            out.append(arg)
    return out


def _run(cmd: list[str], *, cwd: Path | None, timeout: float) -> subprocess.CompletedProcess:
    log.debug("git: {}", _redact_url(cmd))
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={
            **os.environ,
            # Defensive: don't let any pager hang us, don't prompt for
            # credentials, don't honour the user's gitconfig (askpass etc).
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/echo",
            "PAGER": "cat",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )


def _du_mb(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total // (1024 * 1024)


@contextmanager
def clone_pr_branch(
    *,
    workspace: str,
    repo_slug: str,
    source_branch: str,
    bitbucket_username: str,
    bitbucket_app_password: str,
    depth: int = 50,
    max_mb: int = 512,
    timeout: float = 180.0,
) -> Iterator[ClonedRepo]:
    """Clone the PR's source branch into a tmp dir, yield, then nuke it.

    Raises GitCloneError if the clone fails, is too large, or doesn't
    contain the requested branch.
    """
    if not shutil.which("git"):
        raise GitCloneError("git is not installed in this container")

    tmp = Path(tempfile.mkdtemp(prefix="bugbot-clone-", dir="/tmp"))
    try:
        url = _bitbucket_clone_url(
            workspace=workspace,
            repo_slug=repo_slug,
            username=bitbucket_username,
            app_password=bitbucket_app_password,
        )
        cmd = [
            "git", "clone",
            "--depth", str(depth),
            "--single-branch",
            "--branch", source_branch,
            "--no-tags",
            "--filter=blob:limit=1m",  # speed: skip large binary blobs
            url,
            str(tmp / "repo"),
        ]
        try:
            proc = _run(cmd, cwd=None, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise GitCloneError(
                f"git clone timed out after {timeout}s for "
                f"{workspace}/{repo_slug}@{source_branch}"
            ) from exc

        if proc.returncode != 0:
            raise GitCloneError(
                f"git clone failed ({proc.returncode}): "
                f"{redact(proc.stderr.strip())[:500]}"
            )

        repo_path = tmp / "repo"
        size_mb = _du_mb(repo_path)
        if size_mb > max_mb:
            raise GitCloneError(
                f"clone too large: {size_mb} MB > limit {max_mb} MB"
            )
        log.info("cloned {}/{}@{} ({} MB)",
                 workspace, repo_slug, source_branch, size_mb)

        head = _run(["git", "rev-parse", "HEAD"], cwd=repo_path, timeout=10)
        head_commit = head.stdout.strip() if head.returncode == 0 else ""

        yield ClonedRepo(
            path=repo_path,
            workspace=workspace,
            repo_slug=repo_slug,
            branch=source_branch,
            head_commit=head_commit,
        )
    finally:
        # rm -rf even on failure. Don't trust the inner code to leave a
        # tidy state — clones may have been partially populated.
        shutil.rmtree(tmp, ignore_errors=True)
