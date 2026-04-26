"""Rescue routine for orphan recon jobs.

Background
----------
A recon job is created in two phases:

1. A row is inserted into ``recon_jobs`` with ``status='queued'`` and a Celery
   ``task_id`` is stored in ``result_json.celery_task_id``.
2. The worker pulls that message from the Redis broker and executes it.

If the worker (or the broker container) is recreated mid-flight — e.g. during
``docker compose up -d --force-recreate`` triggered by ``--restart`` or ``--all``
in our dev script — Redis can lose the in-flight message even though the AOF
volume is mounted (Celery's redis transport tracks unacked messages in a hash
+ zset that aren't always restored cleanly across abrupt restarts of *both*
the worker and the broker).

When that happens the DB row is stuck on ``status='queued'`` indefinitely,
because nothing is left in the broker to deliver. The Recon UI shows it as
"queued" forever.

This module provides ``rescue_orphan_recon_jobs`` which is run on worker
startup and periodically by Celery beat. It finds jobs that are still
``status='queued'`` and either:

* re-dispatches them onto the appropriate Celery queue (so the worker picks
  them up and runs them now), or
* fails them out with a clear, actionable error if they cannot be redispatched
  (unknown ``kind``, missing target, etc.) — never leaving a row to rot.

Re-dispatch is safe because each task entry now uses ``_claim_for_run`` which
returns immediately if the job is already running or done, so a duplicate
delivery is a no-op.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import dispose_engine, get_session_factory
from app.core.logging import get_logger
from app.modules.recon.models import ReconJob, Target

log = get_logger(__name__)


async def _rescue_one(db: AsyncSession, job: ReconJob) -> str:
    """Best-effort recovery for a single queued job.

    Returns one of: ``redispatched``, ``failed``, ``skipped``.
    """
    target = await db.get(Target, job.target_id)
    if target is None:
        job.status = "failed"
        job.finished_at = datetime.now(tz=timezone.utc)
        job.result_json = {
            **(job.result_json or {}),
            "error": "Recon target was deleted before the job could run.",
        }
        return "failed"

    # Imported lazily to avoid a circular import (workers.py -> celery_app).
    from app.modules.recon import workers as recon_workers  # noqa: WPS433

    task_map = {
        "subdomain": recon_workers.run_subdomain_job,
        "port": recon_workers.run_portscan_job,
        "cve": recon_workers.run_cve_job,
        "webfuzz": recon_workers.run_webfuzz_job,
        "dns": recon_workers.run_dns_job,
        "httprobe": recon_workers.run_httprobe_job,
        "http_headers": recon_workers.run_http_headers_job,
        "tls_cert": recon_workers.run_tls_cert_job,
    }
    task = task_map.get(job.kind)
    if task is None:
        job.status = "failed"
        job.finished_at = datetime.now(tz=timezone.utc)
        job.result_json = {
            **(job.result_json or {}),
            "error": f"Unknown recon job kind '{job.kind}' — cannot redispatch.",
        }
        return "failed"

    params: dict[str, Any] = (job.result_json or {}).get("params", {}) or {}
    try:
        async_result = task.delay(str(job.id), target.value, params)
    except Exception as exc:  # noqa: BLE001
        log.warning("recon.rescue.dispatch_failed", job_id=str(job.id), error=str(exc))
        job.status = "failed"
        job.finished_at = datetime.now(tz=timezone.utc)
        job.result_json = {
            **(job.result_json or {}),
            "error": "Could not redispatch job to Celery — broker unreachable.",
            "detail": str(exc),
        }
        return "failed"

    job.result_json = {
        **(job.result_json or {}),
        "celery_task_id": async_result.id,
        "queue": "recon",
        "rescued_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    return "redispatched"


async def rescue_orphan_recon_jobs() -> dict[str, int]:
    """Find every recon job still in ``queued`` and redispatch / fail it.

    This is intentionally aggressive: if a worker is calling this routine,
    it has either just started up or beat has invoked it on a schedule.
    In both cases any row still flagged ``queued`` is, by construction, a
    candidate for redelivery — the active worker hasn't claimed it yet.
    """
    # Dispose any engine left over from a previous ``asyncio.run`` invocation
    # in this Celery prefork worker. Without this, the connection pool returns
    # connections bound to a closed event loop and SQLAlchemy raises
    # "Task ... attached to a different loop" on the first await.
    await dispose_engine()
    factory = get_session_factory()
    counts = {"redispatched": 0, "failed": 0, "scanned": 0}
    async with factory() as db:
        rows = (
            await db.execute(
                select(ReconJob).where(ReconJob.status == "queued").order_by(ReconJob.id)
            )
        ).scalars().all()
        counts["scanned"] = len(rows)
        for job in rows:
            outcome = await _rescue_one(db, job)
            if outcome in counts:
                counts[outcome] += 1
        if rows:
            await db.commit()

    if counts["scanned"]:
        log.info(
            "recon.rescue.summary",
            scanned=counts["scanned"],
            redispatched=counts["redispatched"],
            failed=counts["failed"],
        )
    return counts


def run_rescue_sync() -> dict[str, int]:
    """Sync wrapper for use from Celery tasks / signal handlers."""
    return asyncio.run(rescue_orphan_recon_jobs())
