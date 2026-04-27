"""Aggregate real metrics from existing SIEM / recon / IDS / vault tables."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ids.models import Inference
from app.modules.recon.models import Finding, ReconJob, Target
from app.modules.siem.models import Alert, Event, Investigation
from app.modules.vault.models import VaultObject


async def build_surface(db: AsyncSession, user_id: uuid.UUID) -> dict[str, int]:
    now = datetime.now(tz=timezone.utc)
    t24 = now - timedelta(hours=24)

    n_new = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "new"))).scalar() or 0
    n_ack = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "ack"))).scalar() or 0
    n_ev = (
        (await db.execute(select(func.count(Event.id)).where(Event.timestamp >= t24))).scalar() or 0
    )

    tids = select(Target.id).where(Target.owner_id == user_id)
    rq = (
        await db.execute(
            select(func.count(ReconJob.id)).where(
                ReconJob.target_id.in_(tids), ReconJob.status == "queued"
            )
        )
    ).scalar() or 0
    rr = (
        await db.execute(
            select(func.count(ReconJob.id)).where(
                ReconJob.target_id.in_(tids), ReconJob.status == "running"
            )
        )
    ).scalar() or 0

    jids = select(ReconJob.id).where(ReconJob.target_id.in_(tids))
    nf = (await db.execute(select(func.count(Finding.id)).where(Finding.job_id.in_(jids)))).scalar() or 0

    n_inf = (
        (await db.execute(select(func.count(Inference.id)).where(Inference.timestamp >= t24))).scalar() or 0
    )
    n_atk = (
        (
            await db.execute(
                select(func.count(Inference.id)).where(
                    Inference.timestamp >= t24, Inference.label == "attack"
                )
            )
        ).scalar()
        or 0
    )

    nv = (
        (await db.execute(select(func.count(VaultObject.id)).where(VaultObject.owner_id == user_id)))
        .scalar()
        or 0
    )
    n_inv = (
        (
            await db.execute(
                select(func.count(Investigation.id)).where(Investigation.state == "open")
            )
        ).scalar()
        or 0
    )

    return {
        "siem_alerts_new": int(n_new),
        "siem_alerts_ack": int(n_ack),
        "siem_events_24h": int(n_ev),
        "recon_jobs_queued": int(rq),
        "recon_jobs_running": int(rr),
        "recon_findings_total": int(nf),
        "ids_inferences_24h": int(n_inf),
        "ids_attacks_24h": int(n_atk),
        "vault_files": int(nv),
        "investigations_open": int(n_inv),
    }
