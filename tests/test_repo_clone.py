"""Subprocess-mocked tests for the git-clone service."""

import subprocess
from pathlib import Path

import pytest

from bugbot.services.repo import (
    GitCloneError,
    _bitbucket_clone_url,
    _redact_url,
    clone_pr_branch,
)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def test_clone_url_encodes_special_chars():
    url = _bitbucket_clone_url(
        workspace="ws", repo_slug="r",
        username="user@example.com",
        app_password="p/w:special",
    )
    # @ in username must be encoded so the URL parses correctly.
    assert "user%40example.com" in url
    # / and : in password must be encoded too.
    assert "p%2Fw%3Aspecial" in url
    assert url.endswith("bitbucket.org/ws/r.git")


def test_redact_url_strips_basic_auth_from_cmd():
    cmd = ["git", "clone", "https://u:secret@bitbucket.org/ws/r.git", "/tmp/x"]
    out = _redact_url(cmd)
    assert "secret" not in " ".join(out)
    assert any("***:***@bitbucket.org/ws/r.git" in a for a in out)


def test_clone_pr_branch_cleans_up_tmpdir_on_success(tmp_path, monkeypatch):
    seen_dirs: list[Path] = []

    def fake_run(cmd, *args, **kwargs):
        # Record the destination dir from the clone command for cleanup check.
        if "clone" in cmd:
            dest = Path(cmd[-1])
            dest.mkdir(parents=True, exist_ok=True)
            seen_dirs.append(dest)
            return _completed()
        if cmd[:2] == ["git", "rev-parse"]:
            return _completed(stdout="deadbeef\n")
        return _completed()

    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: "/usr/bin/git")
    monkeypatch.setattr("bugbot.services.repo.subprocess.run", fake_run)

    with clone_pr_branch(
        workspace="ws", repo_slug="r", source_branch="feature",
        bitbucket_username="u", bitbucket_app_password="p",
    ) as clone:
        assert clone.head_commit == "deadbeef"
        assert clone.path.exists()

    # After exit the parent tmp dir is gone.
    for d in seen_dirs:
        assert not d.parent.exists()


def test_clone_pr_branch_raises_when_git_missing(monkeypatch):
    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: None)
    with pytest.raises(GitCloneError):
        with clone_pr_branch(
            workspace="ws", repo_slug="r", source_branch="b",
            bitbucket_username="u", bitbucket_app_password="p",
        ):
            pass


def test_clone_pr_branch_raises_on_nonzero_exit_and_redacts(monkeypatch):
    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: "/usr/bin/git")

    def boom(*a, **kw):
        return _completed(
            stderr="fatal: could not read from https://u:supersecret@bitbucket.org/ws/r.git",
            returncode=128,
        )

    monkeypatch.setattr("bugbot.services.repo.subprocess.run", boom)

    with pytest.raises(GitCloneError) as ei:
        with clone_pr_branch(
            workspace="ws", repo_slug="r", source_branch="b",
            bitbucket_username="u", bitbucket_app_password="supersecret",
        ):
            pass
    msg = str(ei.value)
    assert "supersecret" not in msg
    assert "u:supersecret" not in msg


def test_clone_pr_branch_raises_on_timeout(monkeypatch):
    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: "/usr/bin/git")

    def slow(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr("bugbot.services.repo.subprocess.run", slow)

    with pytest.raises(GitCloneError) as ei:
        with clone_pr_branch(
            workspace="ws", repo_slug="r", source_branch="b",
            bitbucket_username="u", bitbucket_app_password="p",
            timeout=1,
        ):
            pass
    assert "timed out" in str(ei.value)


def test_clone_pr_branch_rejects_oversized_clone(monkeypatch, tmp_path):
    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: "/usr/bin/git")

    def fake_run(cmd, *args, **kwargs):
        if "clone" in cmd:
            dest = Path(cmd[-1])
            dest.mkdir(parents=True, exist_ok=True)
            # Write a fake 2 MB blob.
            (dest / "big.bin").write_bytes(b"x" * (2 * 1024 * 1024))
            return _completed()
        return _completed(stdout="abc\n")

    monkeypatch.setattr("bugbot.services.repo.subprocess.run", fake_run)

    with pytest.raises(GitCloneError) as ei:
        with clone_pr_branch(
            workspace="ws", repo_slug="r", source_branch="b",
            bitbucket_username="u", bitbucket_app_password="p",
            max_mb=1,  # 1 MB cap → 2 MB clone fails.
        ):
            pass
    assert "too large" in str(ei.value)


def test_clone_pr_branch_sets_credential_blocking_env(monkeypatch):
    monkeypatch.setattr("bugbot.services.repo.shutil.which", lambda _x: "/usr/bin/git")
    captured_env: dict = {}

    def fake_run(cmd, *args, **kwargs):
        captured_env.update(kwargs.get("env") or {})
        if "clone" in cmd:
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return _completed()
        return _completed(stdout="abc\n")

    monkeypatch.setattr("bugbot.services.repo.subprocess.run", fake_run)

    with clone_pr_branch(
        workspace="ws", repo_slug="r", source_branch="b",
        bitbucket_username="u", bitbucket_app_password="p",
    ):
        pass

    # Critical hardening: no interactive password prompts allowed.
    assert captured_env.get("GIT_TERMINAL_PROMPT") == "0"
    assert captured_env.get("GIT_ASKPASS") == "/bin/echo"
    # User's git config must not influence the clone (could contain
    # credential helpers, hooks, etc.).
    assert captured_env.get("GIT_CONFIG_GLOBAL") == "/dev/null"
    assert captured_env.get("GIT_CONFIG_SYSTEM") == "/dev/null"
