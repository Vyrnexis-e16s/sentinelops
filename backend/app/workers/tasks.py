"""Celery task registry. Re-exports tasks from each module so the worker finds them."""
from __future__ import annotations

from app.workers.celery_app import celery_app

# Re-import the recon tasks so Celery's autodiscover picks them up.
try:
    from app.modules.recon.workers import (  # noqa: F401
        run_subdomain_job,
        run_portscan_job,
        run_cve_job,
        run_webfuzz_job,
    )
except Exception:  # pragma: no cover
    # Recon workers are optional in test/dev contexts where the module's
    # network deps may not be installed.
    pass


@celery_app.task(name="ops.ping")
def ping() -> str:
    """Sanity task — `celery -A app.workers.celery_app call ops.ping`."""
    return "pong"
