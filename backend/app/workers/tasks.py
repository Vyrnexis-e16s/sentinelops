"""Celery task registry. Re-exports tasks from each module so the worker finds them.

Imports are eager and *not* wrapped in a silent try/except — if a module fails
to import, the worker must fail fast so the operator sees it instead of the
tasks silently going missing from the registry.
"""
from __future__ import annotations

from app.workers.celery_app import celery_app

from app.modules.recon.workers import (  # noqa: F401
    run_subdomain_job,
    run_portscan_job,
    run_cve_job,
    run_webfuzz_job,
)


@celery_app.task(name="ops.ping")
def ping() -> str:
    """Sanity task — `celery -A app.workers.celery_app call ops.ping`."""
    return "pong"
