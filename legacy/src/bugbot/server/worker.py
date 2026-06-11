"""In-process bounded job runner.

Webhook handler enqueues a review job and returns 202 immediately. A small
pool of threads (size = settings.max_concurrent_reviews) pulls jobs and
runs them via the `Reviewer`. Bounded queue + drop-when-full to keep
memory predictable under burst load.

For scale beyond a single VPS, swap this for Redis + RQ / Celery. The
public surface (`submit_review`) stays the same.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Literal

from bugbot.clients._provider import PullRequestProvider
from bugbot.clients.bitbucket import BitbucketClient
from bugbot.clients.claude_cli import ClaudeCliClient
from bugbot.clients.github import GitHubClient
from bugbot.config import Settings
from bugbot.libs.logging import get_logger
from bugbot.services.review import Reviewer

log = get_logger("worker")


Provider = Literal["bitbucket", "github"]


@dataclass(frozen=True)
class ReviewJob:
    workspace: str
    repo_slug: str
    pr_id: int
    provider: Provider = "bitbucket"
    # Picked by the URL path the webhook posted to:
    #   /webhook/{provider}            → settings.default_domain
    #   /webhook/{provider}/{domain}   → that domain (validated upstream)
    domain: str = "general"


class WorkerConfigError(RuntimeError):
    """Job arrived for a provider that wasn't configured at startup."""


class ReviewWorker:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._pool = ThreadPoolExecutor(
            max_workers=settings.max_concurrent_reviews,
            thread_name_prefix="bugbot-review",
        )
        # Dedupe keys include the provider — same repo name across
        # Bitbucket and GitHub mustn't collide.
        self._inflight: set[tuple[str, str, str, int]] = set()
        self._lock = threading.Lock()
        # Hook for tests to substitute the runner.
        self._runner: Callable[[ReviewJob], None] = self._run_review

    def submit(self, job: ReviewJob) -> bool:
        """Enqueue a job. Returns False if the same PR is already in-flight
        (idempotency under rapid webhook fan-out)."""
        key = (job.provider, job.workspace, job.repo_slug, job.pr_id)
        with self._lock:
            if key in self._inflight:
                log.info("dedupe: job already in-flight {}", key)
                return False
            self._inflight.add(key)
        self._pool.submit(self._wrap, job, key)
        return True

    def _wrap(self, job: ReviewJob, key: tuple) -> None:
        try:
            self._runner(job)
        except Exception as exc:
            log.exception("review failed for {}: {}", key, exc)
        finally:
            with self._lock:
                self._inflight.discard(key)

    def _build_provider(self, job: ReviewJob) -> PullRequestProvider:
        s = self._s
        if job.provider == "bitbucket":
            if s.bitbucket_app_password is None:
                raise WorkerConfigError(
                    "Bitbucket job arrived but BUGBOT_BITBUCKET_APP_PASSWORD "
                    "is not configured"
                )
            return BitbucketClient(
                username=s.bitbucket_username,
                app_password=s.bitbucket_app_password.get_secret_value(),
                workspace=job.workspace,
                repo_slug=job.repo_slug,
                base_url=s.bitbucket_base_url,
                timeout=s.bitbucket_timeout_seconds,
            )
        if job.provider == "github":
            if s.github_token is None:
                raise WorkerConfigError(
                    "GitHub job arrived but BUGBOT_GITHUB_TOKEN is not "
                    "configured"
                )
            return GitHubClient(
                token=s.github_token.get_secret_value(),
                owner=job.workspace,
                repo=job.repo_slug,
                base_url=s.github_base_url,
                timeout=s.github_timeout_seconds,
            )
        raise WorkerConfigError(f"unknown provider {job.provider!r}")

    def _run_review(self, job: ReviewJob) -> None:
        s = self._s
        log.info("starting review {}:{}/{}#{} (domain={})",
                 job.provider, job.workspace, job.repo_slug, job.pr_id,
                 job.domain)
        provider = self._build_provider(job)
        claude = ClaudeCliClient(
            cli_path=s.claude_cli_path,
            model=s.claude_model,
            timeout=s.claude_timeout_seconds,
        )
        with provider, claude:  # type: ignore[arg-type]
            Reviewer(s, provider=provider, claude=claude).run(
                job.pr_id, domain=job.domain,
            )

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=False)
