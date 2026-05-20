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
from typing import Callable

from bugbot.clients.bitbucket import BitbucketClient
from bugbot.clients.claude_cli import ClaudeCliClient
from bugbot.config import Settings
from bugbot.libs.logging import get_logger
from bugbot.services.review import Reviewer

log = get_logger("worker")


@dataclass(frozen=True)
class ReviewJob:
    workspace: str
    repo_slug: str
    pr_id: int


class ReviewWorker:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._pool = ThreadPoolExecutor(
            max_workers=settings.max_concurrent_reviews,
            thread_name_prefix="bugbot-review",
        )
        self._inflight: set[tuple[str, str, int]] = set()
        self._lock = threading.Lock()
        # Hook for tests to substitute the runner.
        self._runner: Callable[[ReviewJob], None] = self._run_review

    def submit(self, job: ReviewJob) -> bool:
        """Enqueue a job. Returns False if the same PR is already in-flight
        (idempotency under rapid webhook fan-out)."""
        key = (job.workspace, job.repo_slug, job.pr_id)
        with self._lock:
            if key in self._inflight:
                log.info("dedupe: job already in-flight {}", key)
                return False
            self._inflight.add(key)
        self._pool.submit(self._wrap, job, key)
        return True

    def _wrap(self, job: ReviewJob, key: tuple[str, str, int]) -> None:
        try:
            self._runner(job)
        except Exception as exc:
            log.exception("review failed for {}: {}", key, exc)
        finally:
            with self._lock:
                self._inflight.discard(key)

    def _run_review(self, job: ReviewJob) -> None:
        s = self._s
        log.info("starting review {}/{}#{}", job.workspace, job.repo_slug, job.pr_id)
        bb = BitbucketClient(
            username=s.bitbucket_username,
            app_password=s.bitbucket_app_password.get_secret_value(),
            workspace=job.workspace,
            repo_slug=job.repo_slug,
            base_url=s.bitbucket_base_url,
            timeout=s.bitbucket_timeout_seconds,
        )
        claude = ClaudeCliClient(
            cli_path=s.claude_cli_path,
            model=s.claude_model,
            timeout=s.claude_timeout_seconds,
        )
        with bb, claude:
            Reviewer(s, bitbucket=bb, claude=claude).run(job.pr_id)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=False)
