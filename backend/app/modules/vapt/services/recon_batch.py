"""Batch enqueue recon jobs for VAPT orchestration (no exploits — only existing recon kinds)."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationAppError
from app.core.logging import get_logger
from app.models.user import User
from app.modules.recon.allowlist import target_matches_allowlist
from app.modules.recon.models import ReconJob, Target
from app.services.audit import AuditService

log = get_logger(__name__)

ALLOWED_KINDS = frozenset(
    {
        "subdomain",
        "port",
        "cve",
        "webfuzz",
        "dns",
        "httprobe",
        "http_headers",
        "tls_cert",
        "ct",
        "wellknown",
        "fingerprint",
        "ptr",
    }
)


def infer_target_kind(value: str) -> str:
    v = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", v):
        return "cidr"
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
        return "host"
    return "domain"


async def get_or_create_target(
    db: AsyncSession, user: User, value: str, audit: AuditService
) -> Target:
    if not target_matches_allowlist(value):
        from app.core.errors import ForbiddenError

        raise ForbiddenError(
            "Target is not permitted by RECON_TARGET_ALLOWLIST. "
            "Add the host, domain, or CIDR, or use an authorised lab target."
        )
    res = await db.execute(select(Target).where(Target.owner_id == user.id, Target.value == value))
    hit = res.scalars().first()
    if hit is not None:
        return hit
    t = Target(
        id=uuid.uuid4(),
        kind=infer_target_kind(value),
        value=value,
        owner_id=user.id,
    )
    db.add(t)
    await audit.append(
        actor_id=user.id,
        action="recon.target.create",
        resource_type="recon_target",
        resource_id=str(t.id),
        metadata={"kind": t.kind, "value": value, "source": "vapt.orchestrate"},
    )
    await db.commit()
    await db.refresh(t)
    return t


async def enqueue_recon_kinds(
    db: AsyncSession,
    user: User,
    *,
    target_value: str,
    kinds: list[str],
    default_params: dict[str, Any],
    per_kind_params: dict[str, dict[str, Any]] | None,
    audit: AuditService,
) -> list[dict[str, Any]]:
    """Create one ReconJob per kind and dispatch Celery. Returns list of {id, kind, status}."""
    if not kinds:
        return []
    bad = [k for k in kinds if k not in ALLOWED_KINDS]
    if bad:
        raise ValidationAppError(f"Unsupported kind(s): {bad}. Allowed: {sorted(ALLOWED_KINDS)}")

    target = await get_or_create_target(db, user, target_value, audit)
    from app.modules.recon import workers  # noqa: WPS433

    task_map: dict[str, Any] = {
        "subdomain": workers.run_subdomain_job,
        "port": workers.run_portscan_job,
        "cve": workers.run_cve_job,
        "webfuzz": workers.run_webfuzz_job,
        "dns": workers.run_dns_job,
        "httprobe": workers.run_httprobe_job,
        "http_headers": workers.run_http_headers_job,
        "tls_cert": workers.run_tls_cert_job,
    }

    out: list[dict[str, Any]] = []
    pextra = per_kind_params or {}
    for kind in kinds:
        p = {**default_params, **(pextra.get(kind) or {})}
        job = ReconJob(
            id=uuid.uuid4(),
            target_id=target.id,
            kind=kind,
            status="queued",
            result_json={"params": p},
        )
        db.add(job)
        await audit.append(
            actor_id=user.id,
            action="recon.job.enqueue",
            resource_type="recon_job",
            resource_id=str(job.id),
            metadata={"kind": kind, "target": target.value, "source": "vapt.orchestrate"},
        )
        await db.commit()
        await db.refresh(job)
        st = "queued"
        try:
            task = task_map.get(kind)
            if task is not None:
                async_result = task.delay(str(job.id), target.value, p)
                job.result_json = {
                    **(job.result_json or {}),
                    "celery_task_id": async_result.id,
                    "queue": "recon",
                }
                await db.commit()
                await db.refresh(job)
        except Exception as exc:  # noqa: BLE001
            log.warning("vapt.orchestrate.enqueue_failed", job_id=str(job.id), error=str(exc))
            job.status = "failed"
            job.finished_at = datetime.now(tz=timezone.utc)
            job.result_json = {
                **(job.result_json or {}),
                "error": "Failed to enqueue recon job. Check Redis/Celery worker.",
                "detail": str(exc),
            }
            st = "failed"
            await db.commit()
            await db.refresh(job)
        out.append({"id": str(job.id), "kind": kind, "status": st})
    return out
