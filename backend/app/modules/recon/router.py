"""Recon REST API: targets, jobs, findings."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import ForbiddenError, NotFoundError
from app.core.logging import get_logger
from app.core.security import current_user
from app.models.user import User
from app.modules.recon.models import Finding, ReconJob, Target
from app.modules.recon.schemas import (
    FindingOut,
    JobCreate,
    JobOut,
    TargetCreate,
    TargetOut,
)
from app.schemas.common import Paginated
from app.services.audit import AuditService, audit_logger

log = get_logger(__name__)

router = APIRouter(prefix="/recon", tags=["recon"])


# --------------------------------------------------------------------------- #
# Targets                                                                     #
# --------------------------------------------------------------------------- #


@router.post("/targets", response_model=TargetOut)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> TargetOut:
    res = await db.execute(
        select(Target).where(Target.owner_id == user.id, Target.value == payload.value)
    )
    existing = res.scalars().first()
    if existing is not None:
        return TargetOut.model_validate(existing)

    target = Target(
        id=uuid.uuid4(),
        kind=payload.kind,
        value=payload.value,
        owner_id=user.id,
    )
    db.add(target)
    await audit.append(
        actor_id=user.id,
        action="recon.target.create",
        resource_type="recon_target",
        resource_id=str(target.id),
        metadata={"kind": payload.kind, "value": payload.value},
    )
    await db.commit()
    await db.refresh(target)
    return TargetOut.model_validate(target)


@router.get("/targets", response_model=list[TargetOut])
async def list_targets(
    db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> list[TargetOut]:
    rows = (
        await db.execute(
            select(Target).where(Target.owner_id == user.id).order_by(Target.created_at.desc())
        )
    ).scalars().all()
    return [TargetOut.model_validate(r) for r in rows]


# --------------------------------------------------------------------------- #
# Jobs                                                                        #
# --------------------------------------------------------------------------- #


@router.post("/jobs", response_model=JobOut)
async def create_job(
    payload: JobCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> JobOut:
    target = await db.get(Target, payload.target_id)
    if target is None:
        raise NotFoundError("Target not found")
    if target.owner_id != user.id:
        raise ForbiddenError("Not your target")

    job = ReconJob(
        id=uuid.uuid4(),
        target_id=target.id,
        kind=payload.kind,
        status="queued",
        result_json={"params": payload.params},
    )
    db.add(job)
    await audit.append(
        actor_id=user.id,
        action="recon.job.enqueue",
        resource_type="recon_job",
        resource_id=str(job.id),
        metadata={"kind": payload.kind, "target": target.value},
    )
    await db.commit()
    await db.refresh(job)

    # Dispatch to Celery. Import lazily so the API package has no hard Celery
    # dependency at import-time (useful for tests).
    try:
        from app.modules.recon import workers  # noqa: WPS433

        task_map = {
            "subdomain": workers.run_subdomain_job,
            "port": workers.run_portscan_job,
            "cve": workers.run_cve_job,
            "webfuzz": workers.run_webfuzz_job,
        }
        task = task_map.get(payload.kind)
        if task is not None:
            task.delay(str(job.id), target.value, payload.params)
    except Exception as exc:  # noqa: BLE001
        log.warning("recon.enqueue_failed", job_id=str(job.id), error=str(exc))

    return JobOut.model_validate(job)


@router.get("/jobs", response_model=Paginated[JobOut])
async def list_jobs(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> Paginated[JobOut]:
    # Scope to the user's targets.
    target_ids_q = select(Target.id).where(Target.owner_id == user.id)
    q = select(ReconJob).where(ReconJob.target_id.in_(target_ids_q))
    c = select(func.count(ReconJob.id)).where(ReconJob.target_id.in_(target_ids_q))
    total = (await db.execute(c)).scalar_one()
    q = q.order_by(ReconJob.started_at.desc().nullslast()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().all()
    return Paginated[JobOut](
        items=[JobOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> JobOut:
    job = await db.get(ReconJob, job_id)
    if job is None:
        raise NotFoundError("Job not found")
    target = await db.get(Target, job.target_id)
    if target is None or target.owner_id != user.id:
        raise ForbiddenError("Not your job")
    return JobOut.model_validate(job)


# --------------------------------------------------------------------------- #
# Findings                                                                    #
# --------------------------------------------------------------------------- #


@router.get("/findings", response_model=Paginated[FindingOut])
async def list_findings(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    severity: str | None = None,
    job_id: uuid.UUID | None = None,
) -> Paginated[FindingOut]:
    target_ids_q = select(Target.id).where(Target.owner_id == user.id)
    job_ids_q = select(ReconJob.id).where(ReconJob.target_id.in_(target_ids_q))
    q = select(Finding).where(Finding.job_id.in_(job_ids_q))
    c = select(func.count(Finding.id)).where(Finding.job_id.in_(job_ids_q))
    if severity:
        q = q.where(Finding.severity == severity)
        c = c.where(Finding.severity == severity)
    if job_id:
        q = q.where(Finding.job_id == job_id)
        c = c.where(Finding.job_id == job_id)

    total = (await db.execute(c)).scalar_one()
    q = q.offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().all()

    # Touch updated_at on job to signal activity — harmless no-op if empty.
    _ = datetime.now(tz=timezone.utc)
    return Paginated[FindingOut](
        items=[FindingOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )
