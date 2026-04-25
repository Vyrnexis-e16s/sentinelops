"""Celery application instance.

Run with:  ``celery -A app.workers.celery_app worker --loglevel=info``
"""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

celery_app = Celery(
    "sentinelops",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=2,
    task_track_started=True,
    task_time_limit=60 * 30,        # 30 min hard limit
    task_soft_time_limit=60 * 25,   # 25 min soft limit
    # Visibility timeout controls how long the broker waits before
    # redelivering a message the worker has prefetched but not acknowledged.
    # Default is 1 hour, which is way too long for a security tool — drop it
    # to 5 minutes so a crashed worker doesn't make the user wait forever.
    broker_transport_options={"visibility_timeout": 300},
    result_backend_transport_options={"visibility_timeout": 300},
    task_routes={
        "recon.*": {"queue": "recon"},
        "siem.*": {"queue": "siem"},
        "ids.*": {"queue": "ids"},
    },
    beat_schedule={
        # Re-dispatch any recon job that's been stuck in 'queued' state because
        # a worker crashed mid-flight or the broker lost the message during a
        # forced container recreate. Cheap query (status='queued' is indexed).
        "recon-rescue-orphans": {
            "task": "recon.rescue",
            "schedule": crontab(minute="*"),  # every minute
        },
    },
)


@worker_ready.connect
def _kick_recon_rescue_on_startup(sender=None, **_kwargs) -> None:  # noqa: ANN001
    """When a worker comes online, immediately rescue any orphan recon jobs.

    This catches the very case the periodic schedule was designed for:
    a forced container recreate (``--restart`` / ``--all``) wipes the
    in-flight Celery messages from Redis, leaving the DB rows flagged
    'queued' with no broker counterpart. As soon as the new worker is up,
    we redispatch those jobs onto the live broker so they actually run.
    """
    try:
        sender.app.send_task("recon.rescue", queue="recon")
        log.info("recon.rescue.startup_kick.scheduled")
    except Exception as exc:  # noqa: BLE001
        log.warning("recon.rescue.startup_kick.failed", error=str(exc))
