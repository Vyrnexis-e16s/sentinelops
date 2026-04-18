"""Celery tasks that run Recon services and persist results.

These tasks synchronously orchestrate async work via ``asyncio.run``. The
service helpers themselves are fully async and respect
``RECON_MAX_CONCURRENCY`` / ``RECON_TIMEOUT_SECONDS``.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session_factory
from app.core.logging import get_logger
from app.core.redis import init_redis
from app.modules.recon.models import Finding, ReconJob
from app.modules.recon.services.cve import query_cves
from app.modules.recon.services.portscan import scan_host
from app.modules.recon.services.subdomain import enumerate_subdomains
from app.modules.recon.services.webfuzz import fuzz_paths
from app.services.events import CHANNEL_RECON, publish
from app.workers.celery_app import celery_app

log = get_logger(__name__)


# --------------------------------------------------------------------------- #
# DB helpers                                                                  #
# --------------------------------------------------------------------------- #


async def _set_status(db: AsyncSession, job_id: uuid.UUID, status: str) -> ReconJob | None:
    job = await db.get(ReconJob, job_id)
    if job is None:
        return None
    job.status = status
    if status == "running" and job.started_at is None:
        job.started_at = datetime.now(tz=timezone.utc)
    if status in {"done", "failed"}:
        job.finished_at = datetime.now(tz=timezone.utc)
    await db.flush()
    return job


async def _persist_findings(
    db: AsyncSession, job_id: uuid.UUID, findings: list[dict[str, Any]]
) -> int:
    count = 0
    for f in findings:
        db.add(
            Finding(
                id=uuid.uuid4(),
                job_id=job_id,
                severity=f.get("severity", "info"),
                title=f["title"],
                description=f.get("description", ""),
                evidence_json=f.get("evidence", {}),
            )
        )
        count += 1
    await db.flush()
    return count


# --------------------------------------------------------------------------- #
# Async runners                                                               #
# --------------------------------------------------------------------------- #


async def _run_subdomain(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    factory = get_session_factory()
    wl = params.get("wordlist")
    async with factory() as db:
        job = await _set_status(db, uuid.UUID(job_id), "running")
        if job is None:
            return {"error": "missing_job"}
        try:
            hits = await enumerate_subdomains(target, wordlist=wl)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.subdomain.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        findings = [
            {
                "severity": "info",
                "title": f"Subdomain live: {h.name}",
                "description": f"Resolved {h.name}",
                "evidence": {"a": h.a_records, "aaaa": h.aaaa_records},
            }
            for h in hits
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = {"count": len(hits), "hits": [h.name for h in hits]}
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "subdomain", "count": len(findings)})
    return {"hits": len(findings)}


async def _run_portscan(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    factory = get_session_factory()
    ports = params.get("ports")
    async with factory() as db:
        job = await _set_status(db, uuid.UUID(job_id), "running")
        if job is None:
            return {"error": "missing_job"}
        try:
            results = await scan_host(target, ports=ports)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.portscan.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        open_results = [r for r in results if r.state == "open"]
        findings = [
            {
                "severity": "low",
                "title": f"Open TCP port {r.port} on {target}",
                "description": r.banner or "",
                "evidence": {"port": r.port, "banner": r.banner},
            }
            for r in open_results
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = {"open": [r.port for r in open_results], "tested": len(results)}
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "port", "count": len(findings)})
    return {"open": len(findings)}


async def _run_cve(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    factory = get_session_factory()
    redis = await init_redis()
    cpe = params.get("cpe") or target
    async with factory() as db:
        job = await _set_status(db, uuid.UUID(job_id), "running")
        if job is None:
            return {"error": "missing_job"}
        try:
            summary = await query_cves(cpe, redis=redis)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.cve.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        findings = [
            {
                "severity": v.get("severity", "unknown"),
                "title": f"{v['cve_id']} affects {cpe}",
                "description": v.get("summary", ""),
                "evidence": v,
            }
            for v in summary.get("vulnerabilities", [])
            if v.get("cve_id")
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = summary
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "cve", "count": len(findings)})
    return {"cves": len(findings)}


async def _run_webfuzz(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    factory = get_session_factory()
    wl = params.get("wordlist")
    base = target if target.startswith("http") else f"http://{target}"
    async with factory() as db:
        job = await _set_status(db, uuid.UUID(job_id), "running")
        if job is None:
            return {"error": "missing_job"}
        try:
            hits = await fuzz_paths(base, wordlist=wl)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.webfuzz.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        findings = [
            {
                "severity": "medium" if h.status in {200, 401, 403} else "low",
                "title": f"{base}/{h.path} -> {h.status}",
                "description": h.content_type or "",
                "evidence": {"path": h.path, "status": h.status,
                             "length": h.content_length, "content_type": h.content_type},
            }
            for h in hits
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = {"hits": [{"path": h.path, "status": h.status} for h in hits]}
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "webfuzz", "count": len(findings)})
    return {"hits": len(findings)}


# --------------------------------------------------------------------------- #
# Celery task wrappers                                                        #
# --------------------------------------------------------------------------- #


@celery_app.task(name="recon.subdomain")
def run_subdomain_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_subdomain(job_id, target, params or {}))


@celery_app.task(name="recon.port")
def run_portscan_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_portscan(job_id, target, params or {}))


@celery_app.task(name="recon.cve")
def run_cve_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_cve(job_id, target, params or {}))


@celery_app.task(name="recon.webfuzz")
def run_webfuzz_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_webfuzz(job_id, target, params or {}))
