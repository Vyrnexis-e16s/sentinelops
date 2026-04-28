"""Recon REST API: targets, jobs, findings, schedules, diff, export, graph."""
from __future__ import annotations

import csv
import io
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import ForbiddenError, NotFoundError
from app.core.logging import get_logger
from app.core.security import current_user
from app.models.user import User
from app.modules.recon.allowlist import target_matches_allowlist
from app.modules.recon.models import Finding, ReconJob, ReconSchedule, Target
from app.modules.recon.schemas import (
    DiffEntry,
    DiffResult,
    FindingOut,
    GraphEdge,
    GraphNode,
    GraphOut,
    JobCreate,
    JobOut,
    ScheduleCreate,
    ScheduleOut,
    ScheduleUpdate,
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
    if not target_matches_allowlist(payload.value):
        raise ForbiddenError(
            "Target is not permitted by RECON_TARGET_ALLOWLIST. "
            "Add this host, domain suffix, or CIDR to the allowlist, or clear it for local-only use."
        )

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
            "dns": workers.run_dns_job,
            "httprobe": workers.run_httprobe_job,
            "http_headers": workers.run_http_headers_job,
            "tls_cert": workers.run_tls_cert_job,
            "ct": workers.run_ct_job,
            "wellknown": workers.run_wellknown_job,
            "fingerprint": workers.run_fingerprint_job,
            "ptr": workers.run_ptr_job,
            "takeover": workers.run_takeover_job,
            "axfr": workers.run_axfr_job,
            "robots_sitemap": workers.run_robots_sitemap_job,
            "js_endpoints": workers.run_js_endpoints_job,
            "cookie_audit": workers.run_cookie_audit_job,
            "tls_audit": workers.run_tls_audit_job,
            "wayback": workers.run_wayback_job,
        }
        task = task_map.get(payload.kind)
        if task is not None:
            async_result = task.delay(str(job.id), target.value, payload.params)
            job.result_json = {
                **(job.result_json or {}),
                "celery_task_id": async_result.id,
                "queue": "recon",
            }
            await db.commit()
            await db.refresh(job)
    except Exception as exc:  # noqa: BLE001
        log.warning("recon.enqueue_failed", job_id=str(job.id), error=str(exc))
        job.status = "failed"
        job.finished_at = datetime.now(tz=timezone.utc)
        job.result_json = {
            **(job.result_json or {}),
            "error": "Failed to enqueue recon job. Check Redis/Celery worker.",
            "detail": str(exc),
        }
        await db.commit()
        await db.refresh(job)

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


@router.post("/jobs/{job_id}/retry", response_model=JobOut)
async def retry_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> JobOut:
    """Re-dispatch a recon job that's stuck queued or has previously failed.

    Why this exists: if a worker or broker container is recreated mid-flight
    (e.g. ``docker compose up --force-recreate``), a job's Celery message
    can be lost while the DB row still says ``status='queued'``. Rather
    than asking the user to delete and recreate the job, we expose this
    explicit retry hook so they can recover with a single click.

    Only the target's owner can retry. Jobs that are currently ``running``
    are left alone — re-issuing them while the worker is mid-task would be
    a footgun. The worker tasks themselves are now idempotent
    (``_claim_for_run``) so even a duplicate delivery is safe.
    """
    job = await db.get(ReconJob, job_id)
    if job is None:
        raise NotFoundError("Job not found")
    target = await db.get(Target, job.target_id)
    if target is None or target.owner_id != user.id:
        raise ForbiddenError("Not your job")

    if job.status == "running":
        raise ForbiddenError(
            "Job is currently running. Wait for it to finish, or stop the worker first."
        )

    job.status = "queued"
    job.started_at = None
    job.finished_at = None
    existing = job.result_json or {}
    job.result_json = {
        "params": existing.get("params", {}),
        "retried_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    try:
        from app.modules.recon import workers  # noqa: WPS433

        task_map = {
            "subdomain": workers.run_subdomain_job,
            "port": workers.run_portscan_job,
            "cve": workers.run_cve_job,
            "webfuzz": workers.run_webfuzz_job,
            "dns": workers.run_dns_job,
            "httprobe": workers.run_httprobe_job,
            "http_headers": workers.run_http_headers_job,
            "tls_cert": workers.run_tls_cert_job,
            "ct": workers.run_ct_job,
            "wellknown": workers.run_wellknown_job,
            "fingerprint": workers.run_fingerprint_job,
            "ptr": workers.run_ptr_job,
            "takeover": workers.run_takeover_job,
            "axfr": workers.run_axfr_job,
            "robots_sitemap": workers.run_robots_sitemap_job,
            "js_endpoints": workers.run_js_endpoints_job,
            "cookie_audit": workers.run_cookie_audit_job,
            "tls_audit": workers.run_tls_audit_job,
            "wayback": workers.run_wayback_job,
        }
        task = task_map.get(job.kind)
        if task is None:
            raise ValueError(f"Unknown recon kind '{job.kind}'")
        async_result = task.delay(str(job.id), target.value, job.result_json["params"])
        job.result_json = {
            **(job.result_json or {}),
            "celery_task_id": async_result.id,
            "queue": "recon",
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("recon.retry_failed", job_id=str(job.id), error=str(exc))
        job.status = "failed"
        job.finished_at = datetime.now(tz=timezone.utc)
        job.result_json = {
            **(job.result_json or {}),
            "error": "Failed to enqueue retry. Check Redis/Celery worker.",
            "detail": str(exc),
        }

    await audit.append(
        actor_id=user.id,
        action="recon.job.retry",
        resource_type="recon_job",
        resource_id=str(job.id),
        metadata={"kind": job.kind, "target": target.value, "status": job.status},
    )
    await db.commit()
    await db.refresh(job)
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
    q = (
        select(Finding)
        .join(ReconJob, Finding.job_id == ReconJob.id)
        .where(Finding.job_id.in_(job_ids_q))
    )
    c = select(func.count(Finding.id)).where(Finding.job_id.in_(job_ids_q))
    if severity:
        q = q.where(Finding.severity == severity)
        c = c.where(Finding.severity == severity)
    if job_id:
        q = q.where(Finding.job_id == job_id)
        c = c.where(Finding.job_id == job_id)

    total = (await db.execute(c)).scalar_one()
    # Deterministic, newest jobs first (fixes empty "Latest job" when only 50 random rows were returned).
    q = q.order_by(ReconJob.finished_at.desc().nulls_last(), ReconJob.started_at.desc().nulls_last(), Finding.id)
    q = q.offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().all()

    # Touch updated_at on job to signal activity — harmless no-op if empty.
    _ = datetime.now(tz=timezone.utc)
    return Paginated[FindingOut](
        items=[FindingOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


# --------------------------------------------------------------------------- #
# Diff between two completed jobs of the same kind (subdomain / wayback / ...) #
# --------------------------------------------------------------------------- #


def _names_from_job(job: ReconJob) -> set[str]:
    """Pull the canonical 'name set' out of a job's result_json.

    Works for ``subdomain`` (hits[].name), ``ct`` (returned name_value strings),
    ``wayback`` (urls[].path), ``robots_sitemap`` (sitemap_urls + disallow),
    ``js_endpoints`` (paths). Returns a set of strings (deduped, lower-cased).
    """
    r = job.result_json or {}
    out: set[str] = set()
    if job.kind == "subdomain":
        for h in (r.get("hits") or []):
            n = (h.get("name") or "").strip().lower() if isinstance(h, dict) else ""
            if n:
                out.add(n)
    elif job.kind == "wayback":
        for u in (r.get("urls") or []):
            p = (u.get("path") or "").strip() if isinstance(u, dict) else ""
            if p:
                out.add(p)
    elif job.kind == "robots_sitemap":
        for p in (r.get("sitemap_urls") or []):
            if isinstance(p, str):
                out.add(p)
        for p in (r.get("disallow") or []):
            if isinstance(p, str):
                out.add(p)
    elif job.kind == "js_endpoints":
        for p in (r.get("paths") or []):
            if isinstance(p, str):
                out.add(p)
    return out


@router.get("/diff", response_model=DiffResult)
async def diff_jobs(
    target_id: uuid.UUID,
    kind: str = Query(..., description="Job kind to diff (e.g. 'subdomain')"),
    head_job_id: uuid.UUID | None = None,
    base_job_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> DiffResult:
    """Compare two completed jobs of the same kind and return per-name deltas.

    If ``head_job_id`` / ``base_job_id`` are not supplied we pick the two
    most-recent ``done`` jobs for the given target+kind. If only one is
    available we return everything as ``new`` so the UI can still render.
    """
    target = await db.get(Target, target_id)
    if target is None or target.owner_id != user.id:
        raise NotFoundError("Target not found")

    base_q = select(ReconJob).where(
        ReconJob.target_id == target_id,
        ReconJob.kind == kind,
        ReconJob.status == "done",
    ).order_by(ReconJob.finished_at.desc().nullslast())

    if head_job_id is not None:
        head = await db.get(ReconJob, head_job_id)
        if head is None or head.target_id != target_id:
            raise NotFoundError("head_job_id not found for target")
    else:
        head = (await db.execute(base_q.limit(1))).scalars().first()

    if head is None:
        raise NotFoundError(f"No completed '{kind}' jobs for this target yet")

    if base_job_id is not None:
        base = await db.get(ReconJob, base_job_id)
        if base is None or base.target_id != target_id:
            raise NotFoundError("base_job_id not found for target")
    else:
        base = (
            await db.execute(base_q.where(ReconJob.id != head.id).limit(1))
        ).scalars().first()

    head_names = _names_from_job(head)
    base_names = _names_from_job(base) if base is not None else set()

    new = sorted(head_names - base_names)
    removed = sorted(base_names - head_names)
    stable = sorted(head_names & base_names)

    entries: list[DiffEntry] = []
    entries += [DiffEntry(name=n, state="new") for n in new]
    entries += [DiffEntry(name=n, state="removed") for n in removed]
    entries += [DiffEntry(name=n, state="stable") for n in stable]

    return DiffResult(
        target_id=target_id,
        kind=kind,
        base_job_id=base.id if base else None,
        head_job_id=head.id,
        new_count=len(new),
        removed_count=len(removed),
        stable_count=len(stable),
        entries=entries,
    )


# --------------------------------------------------------------------------- #
# Export findings (JSON / CSV / Burp-Scope JSON / Nessus-style XML)           #
# --------------------------------------------------------------------------- #


def _findings_to_csv(rows: list[Finding]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "job_id", "severity", "title", "description"])
    for f in rows:
        w.writerow([
            str(f.id),
            str(f.job_id),
            f.severity,
            f.title,
            (f.description or "").replace("\n", " ").replace("\r", " ")[:1000],
        ])
    return buf.getvalue().encode("utf-8")


def _findings_to_burp_scope(target_value: str, rows: list[Finding]) -> bytes:
    """Burp 'Project scope' JSON. Hosts/URLs distilled from finding evidence."""
    hosts: set[str] = set()
    for f in rows:
        ev = f.evidence_json or {}
        for k in ("url", "name", "host", "domain"):
            v = ev.get(k)
            if isinstance(v, str) and v:
                hosts.add(v)
        for sub in (ev.get("hits") or []):
            if isinstance(sub, dict):
                v = sub.get("name") or sub.get("url")
                if isinstance(v, str):
                    hosts.add(v)
    if target_value:
        hosts.add(target_value)
    payload = {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": [
                    {"enabled": True, "host": h, "port": "", "protocol": "any", "file": ""}
                    for h in sorted(hosts)
                ],
                "exclude": [],
            }
        }
    }
    import json
    return json.dumps(payload, indent=2).encode("utf-8")


def _findings_to_nessus_xml(target_value: str, rows: list[Finding]) -> bytes:
    """Minimal NessusClientData_v2 stub.

    This is *not* a faithful Nessus replication, but most importers (Nexpose,
    Faraday, DefectDojo) will accept this structure as a 'NessusClientData_v2'
    document with custom plugin entries.
    """
    nessus = ET.Element("NessusClientData_v2")
    report = ET.SubElement(nessus, "Report", attrib={"name": f"SentinelOps-{target_value or 'target'}"})
    rh = ET.SubElement(report, "ReportHost", attrib={"name": target_value or "target"})
    for f in rows:
        sev_map = {"info": "0", "low": "1", "medium": "2", "high": "3", "critical": "4"}
        item = ET.SubElement(
            rh,
            "ReportItem",
            attrib={
                "port": "0",
                "svc_name": "general",
                "protocol": "tcp",
                "severity": sev_map.get(f.severity.lower(), "0"),
                "pluginID": str(f.id)[:8],
                "pluginName": f.title[:120],
                "pluginFamily": "SentinelOps Recon",
            },
        )
        ET.SubElement(item, "description").text = f.description or ""
        ET.SubElement(item, "synopsis").text = f.title
        ET.SubElement(item, "risk_factor").text = f.severity.title()
    return ET.tostring(nessus, encoding="utf-8", xml_declaration=True)


@router.get("/export")
async def export_findings(
    fmt: str = Query("json", pattern="^(json|csv|burp|nessus)$"),
    target_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    severity: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> Response:
    """Export findings — supports JSON / CSV / Burp scope / Nessus stub.

    Always scoped to the caller's targets. Optional ``target_id`` / ``job_id``
    / ``severity`` filters narrow the result set.
    """
    target_ids_q = select(Target.id).where(Target.owner_id == user.id)
    if target_id is not None:
        owned = (
            await db.execute(select(Target).where(Target.id == target_id, Target.owner_id == user.id))
        ).scalars().first()
        if owned is None:
            raise NotFoundError("Target not found or not yours")
        target_value = owned.value
        target_ids_q = select(Target.id).where(Target.id == target_id, Target.owner_id == user.id)
    else:
        target_value = ""

    job_ids_q = select(ReconJob.id).where(ReconJob.target_id.in_(target_ids_q))
    if job_id is not None:
        job_ids_q = select(ReconJob.id).where(ReconJob.id == job_id, ReconJob.target_id.in_(target_ids_q))
    q = select(Finding).where(Finding.job_id.in_(job_ids_q))
    if severity:
        q = q.where(Finding.severity == severity)
    q = q.order_by(Finding.id).limit(10_000)
    rows = (await db.execute(q)).scalars().all()

    if fmt == "json":
        import json
        body = json.dumps(
            [
                {
                    "id": str(f.id),
                    "job_id": str(f.job_id),
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence_json,
                }
                for f in rows
            ],
            indent=2,
            default=str,
        ).encode("utf-8")
        return Response(content=body, media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=sentinelops-findings.json"
        })
    if fmt == "csv":
        return Response(content=_findings_to_csv(rows), media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=sentinelops-findings.csv"
        })
    if fmt == "burp":
        return Response(content=_findings_to_burp_scope(target_value, rows), media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=sentinelops-burp-scope.json"
        })
    if fmt == "nessus":
        return Response(content=_findings_to_nessus_xml(target_value, rows), media_type="application/xml", headers={
            "Content-Disposition": "attachment; filename=sentinelops-findings.nessus"
        })
    raise NotFoundError(f"Unsupported export format '{fmt}'")  # safety net


# --------------------------------------------------------------------------- #
# Asset graph                                                                 #
# --------------------------------------------------------------------------- #


@router.get("/graph", response_model=GraphOut)
async def asset_graph(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> GraphOut:
    """Build a node/edge graph from this target's recon findings.

    Edges:
      target -> subdomain (from ``recon.subdomain`` hits)
      subdomain -> ip (from A/AAAA records in subdomain hits)
      ip -> service (from ``recon.port`` open ports)
      target -> cve (from ``recon.cve`` findings)
      target -> takeover-finding (from ``recon.takeover``)
    """
    target = await db.get(Target, target_id)
    if target is None or target.owner_id != user.id:
        raise NotFoundError("Target not found")

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    target_node_id = f"target:{target.value}"
    nodes[target_node_id] = GraphNode(id=target_node_id, label=target.value, type="target")

    jobs = (
        await db.execute(
            select(ReconJob)
            .where(ReconJob.target_id == target_id, ReconJob.status == "done")
            .order_by(ReconJob.finished_at.desc().nullslast())
        )
    ).scalars().all()
    for job in jobs:
        r = job.result_json or {}
        if job.kind == "subdomain":
            for h in (r.get("hits") or []):
                if not isinstance(h, dict):
                    continue
                name = (h.get("name") or "").strip()
                if not name:
                    continue
                sd_id = f"subdomain:{name}"
                nodes.setdefault(sd_id, GraphNode(id=sd_id, label=name, type="subdomain"))
                edges.append(GraphEdge(source=target_node_id, target=sd_id, relation="resolves"))
                for ip in (h.get("a") or []) + (h.get("aaaa") or []):
                    if not isinstance(ip, str) or not ip:
                        continue
                    ip_id = f"ip:{ip}"
                    nodes.setdefault(ip_id, GraphNode(id=ip_id, label=ip, type="ip"))
                    edges.append(GraphEdge(source=sd_id, target=ip_id, relation="A"))
        elif job.kind == "port":
            host = target.value
            ip_id = f"ip:{host}"
            nodes.setdefault(ip_id, GraphNode(id=ip_id, label=host, type="ip"))
            for p in (r.get("open") or []):
                svc_id = f"service:{host}:{p}"
                nodes.setdefault(svc_id, GraphNode(id=svc_id, label=f"{host}:{p}", type="service", meta={"port": p}))
                edges.append(GraphEdge(source=ip_id, target=svc_id, relation="listens"))
        elif job.kind == "cve":
            for v in (r.get("vulnerabilities") or []):
                if not isinstance(v, dict):
                    continue
                cve_id = v.get("cve_id")
                if not cve_id:
                    continue
                cn_id = f"cve:{cve_id}"
                nodes.setdefault(cn_id, GraphNode(id=cn_id, label=cve_id, type="cve", severity=v.get("severity")))
                edges.append(GraphEdge(source=target_node_id, target=cn_id, relation="affected_by"))
        elif job.kind == "takeover":
            for tk in (r.get("vulnerable") or []):
                if not isinstance(tk, dict):
                    continue
                name = (tk.get("name") or "").strip()
                if not name:
                    continue
                sd_id = f"subdomain:{name}"
                nodes.setdefault(sd_id, GraphNode(id=sd_id, label=name, type="subdomain", severity="high", meta={"takeover": tk.get("provider_match")}))
                edges.append(GraphEdge(source=target_node_id, target=sd_id, relation="takeover"))

    return GraphOut(target_id=target_id, nodes=list(nodes.values()), edges=edges)


# --------------------------------------------------------------------------- #
# Schedules                                                                   #
# --------------------------------------------------------------------------- #


@router.post("/schedules", response_model=ScheduleOut)
async def create_schedule(
    payload: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> ScheduleOut:
    target = await db.get(Target, payload.target_id)
    if target is None:
        raise NotFoundError("Target not found")
    if target.owner_id != user.id:
        raise ForbiddenError("Not your target")
    sch = ReconSchedule(
        id=uuid.uuid4(),
        target_id=target.id,
        kind=payload.kind,
        interval_minutes=int(payload.interval_minutes),
        enabled=bool(payload.enabled),
        params_json=dict(payload.params or {}),
        owner_id=user.id,
    )
    db.add(sch)
    await audit.append(
        actor_id=user.id,
        action="recon.schedule.create",
        resource_type="recon_schedule",
        resource_id=str(sch.id),
        metadata={"kind": payload.kind, "target": target.value, "interval_minutes": payload.interval_minutes},
    )
    await db.commit()
    await db.refresh(sch)
    return ScheduleOut.model_validate(sch)


@router.get("/schedules", response_model=list[ScheduleOut])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> list[ScheduleOut]:
    rows = (
        await db.execute(
            select(ReconSchedule)
            .where(ReconSchedule.owner_id == user.id)
            .order_by(ReconSchedule.created_at.desc())
        )
    ).scalars().all()
    return [ScheduleOut.model_validate(r) for r in rows]


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> ScheduleOut:
    sch = await db.get(ReconSchedule, schedule_id)
    if sch is None or sch.owner_id != user.id:
        raise NotFoundError("Schedule not found")
    if payload.interval_minutes is not None:
        sch.interval_minutes = int(payload.interval_minutes)
    if payload.enabled is not None:
        sch.enabled = bool(payload.enabled)
    if payload.params is not None:
        sch.params_json = dict(payload.params)
    await audit.append(
        actor_id=user.id,
        action="recon.schedule.update",
        resource_type="recon_schedule",
        resource_id=str(sch.id),
        metadata={"enabled": sch.enabled, "interval_minutes": sch.interval_minutes},
    )
    await db.commit()
    await db.refresh(sch)
    return ScheduleOut.model_validate(sch)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> dict[str, Any]:
    sch = await db.get(ReconSchedule, schedule_id)
    if sch is None or sch.owner_id != user.id:
        raise NotFoundError("Schedule not found")
    await db.delete(sch)
    await audit.append(
        actor_id=user.id,
        action="recon.schedule.delete",
        resource_type="recon_schedule",
        resource_id=str(schedule_id),
        metadata={},
    )
    await db.commit()
    return {"ok": True, "id": str(schedule_id)}
