"""Celery application instance.

Run with:  ``celery -A app.workers.celery_app worker --loglevel=info``
"""
from __future__ import annotations

from celery import Celery

from app.core.config import settings

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
    task_routes={
        "recon.*": {"queue": "recon"},
        "siem.*": {"queue": "siem"},
        "ids.*": {"queue": "ids"},
    },
    beat_schedule={
        # Reserved for nightly retraining / IOC feed sync.
    },
)
