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

from app.core.db import dispose_engine, get_session_factory
from app.core.logging import get_logger
from app.core.redis import init_redis
from app.modules.recon.models import Finding, ReconJob
from app.modules.recon.services.cve import is_bare_fqdn_not_cpe, query_cves
from app.modules.recon.services.dns_recon import collect_records as collect_dns
from app.modules.recon.services.httprobe import probe as httprobe_urls
from app.modules.recon.services.http_headers import check_security_headers
from app.modules.recon.services.portscan import scan_host
from app.modules.recon.services.tls_info import fetch_peer_info
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


async def _claim_for_run(db: AsyncSession, job_id: uuid.UUID) -> ReconJob | None:
    """Idempotency guard: only proceed when the job is fresh (queued/failed).

    Returns the job in 'running' state ready to execute, or None if another
    worker has already finished or is currently running it. This makes
    re-dispatch (e.g. after the rescue routine resurrects an orphan) safe —
    duplicate deliveries are short-circuited without producing duplicate
    findings.
    """
    job = await db.get(ReconJob, job_id)
    if job is None:
        return None
    if job.status in {"running", "done"}:
        log.info("recon.task.skip", job_id=str(job_id), reason=f"status={job.status}")
        return None
    job.status = "running"
    if job.started_at is None:
        job.started_at = datetime.now(tz=timezone.utc)
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
    await dispose_engine()  # bind engine to *this* asyncio.run loop
    factory = get_session_factory()
    wl = params.get("wordlist")
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
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
                "description": f"Resolved {h.name} ({h.source})",
                "evidence": {
                    "a": h.a_records,
                    "aaaa": h.aaaa_records,
                    "source": h.source,
                },
            }
            for h in hits
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = {
            "count": len(hits),
            "hits": [
                {"name": h.name, "a": h.a_records, "aaaa": h.aaaa_records, "source": h.source}
                for h in hits
            ],
        }
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "subdomain", "count": len(findings)})
    return {"hits": len(findings)}


async def _run_portscan(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    ports = params.get("ports")
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
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
    await dispose_engine()
    factory = get_session_factory()
    redis = await init_redis()
    cpe = (params.get("cpe") or target or "").strip()
    if is_bare_fqdn_not_cpe(cpe):
        body = (
            "CVE jobs query the NIST NVD by CPE, not by domain alone. Use job params, e.g. "
            "`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*` or a shortcut `nginx:1.25`, "
            "or run a port/HTTP job first to choose a CPE. "
            "Set NVD_API_KEY in the API for higher rate limits."
        )
        async with factory() as db:
            job = await _claim_for_run(db, uuid.UUID(job_id))
            if job is None:
                return {"error": "missing_or_already_handled"}
            await _persist_findings(
                db,
                uuid.UUID(job_id),
                [
                    {
                        "severity": "info",
                        "title": f"CVE scan skipped: bare domain {cpe!r} is not a CPE",
                        "description": body,
                        "evidence": {"target": cpe, "kind": "hint"},
                    }
                ],
            )
            job.result_json = {
                "skipped": True,
                "reason": "bare_fqdn",
                "cpe": cpe,
                "hint": body,
            }
            await _set_status(db, uuid.UUID(job_id), "done")
            await db.commit()
        await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "cve", "count": 0})
        return {"cves": 0, "skipped": "bare_fqdn"}

    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
        try:
            summary = await query_cves(cpe, redis=redis)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.cve.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        findings: list[dict[str, Any]] = [
            {
                "severity": v.get("severity", "unknown"),
                "title": f"{v['cve_id']} affects {cpe}",
                "description": v.get("summary", ""),
                "evidence": v,
            }
            for v in summary.get("vulnerabilities", [])
            if v.get("cve_id")
        ]
        nvd_err = summary.get("error")
        if nvd_err and not findings:
            findings.append(
                {
                    "severity": "info",
                    "title": "NVD query returned no CVEs",
                    "description": str(nvd_err),
                    "evidence": {"cpe": summary.get("cpe", cpe), "nvd_error": nvd_err},
                }
            )
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = summary
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()

    cve_only = len(
        [f for f in findings if isinstance(f.get("evidence"), dict) and f["evidence"].get("cve_id")]
    )
    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "cve", "count": cve_only or len(findings)})
    return {"cves": cve_only}


async def _run_webfuzz(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    wl = params.get("wordlist")
    base = target if target.startswith("http") else f"http://{target}"
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
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


def _host_and_port(target: str) -> tuple[str, int | None]:
    from urllib.parse import urlparse

    t = (target or "").strip()
    if not t:
        return ("", None)
    if "://" in t:
        p = urlparse(t)
        return (p.hostname or "", p.port)
    if t.count(":") == 1 and not t.startswith("["):
        a, b = t.rsplit(":", 1)
        if b.isdigit():
            return a, int(b)
    return t.split("/")[0], None


async def _run_dns(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
        try:
            col = await collect_dns(target)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.dns.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        total = sum(len(v) for v in col.get("records", {}).values() if isinstance(v, list))
        findings: list[dict[str, Any]] = [
            {
                "severity": "info",
                "title": f"DNS: {col.get('name', target)}",
                "description": f"{total} record(s) across A/AAAA/MX/NS/TXT/CNAME",
                "evidence": col,
            }
        ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = col
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()
    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "dns", "count": len(findings)})
    return {"records": total}


async def _run_httprobe(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
        try:
            https_only = bool(params.get("https_only", False))
            rows = await httprobe_urls(target, https_only=https_only)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.httprobe.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        finding_rows: list[dict[str, Any]] = []
        for r in rows:
            if r.get("error") is not None:
                finding_rows.append(
                    {
                        "severity": "low",
                        "title": f"HTTP probe: {r.get('url', '')}",
                        "description": r.get("error", ""),
                        "evidence": r,
                    }
                )
            else:
                st = r.get("status", 0)
                finding_rows.append(
                    {
                        "severity": "low",
                        "title": f"HTTP {st} — {r.get('url', '')}",
                        "description": (r.get("title") or r.get("server") or "")
                        and f"{(r.get('title') or '').strip()[:120]} {r.get('server') or ''}".strip(),
                        "evidence": r,
                    }
                )
        if not finding_rows:
            finding_rows = [
                {
                    "severity": "info",
                    "title": "No HTTP response",
                    "description": "Nothing to show",
                    "evidence": {},
                }
            ]
        await _persist_findings(db, uuid.UUID(job_id), finding_rows)
        job.result_json = {"probes": rows}
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()
    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "httprobe", "count": len(finding_rows)})
    return {"probes": len(rows)}


async def _run_http_headers(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
        try:
            https_only = bool(params.get("https_only", False))
            res = await check_security_headers(target, https_only=https_only)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.http_headers.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        if not res.get("ok"):
            findings = [
                {
                    "severity": "medium",
                    "title": "Security headers probe failed",
                    "description": str(res.get("error", "unknown")),
                    "evidence": res,
                }
            ]
        else:
            miss = res.get("headers_missing") or []
            sev = "high" if len(miss) >= 5 else "medium" if len(miss) else "low"
            findings = [
                {
                    "severity": sev,
                    "title": f"Security headers on {res.get('url', '')} — {len(miss)} missing",
                    "description": ", ".join(miss) or "all checked headers present",
                    "evidence": res,
                }
            ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = res
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()
    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "http_headers", "count": len(findings)})
    return {"ok": res.get("ok", False)}


async def _run_tls_cert(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    await dispose_engine()
    factory = get_session_factory()
    h, tport = _host_and_port(target)
    raw = params.get("port", tport)
    if raw is None:
        raw = 443
    try:
        p = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        p = 443
    if p < 1 or p > 65535:
        p = 443
    async with factory() as db:
        job = await _claim_for_run(db, uuid.UUID(job_id))
        if job is None:
            return {"error": "missing_or_already_handled"}
        if not h:
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            return {"error": "Could not parse hostname for TLS (use a host, host:port, or https:// URL)."}
        try:
            info = await fetch_peer_info(h, p)
        except Exception as exc:  # noqa: BLE001
            await _set_status(db, uuid.UUID(job_id), "failed")
            await db.commit()
            log.exception("recon.tls_cert.failed", job_id=job_id, error=str(exc))
            return {"error": str(exc)}

        if not info.get("ok"):
            findings = [
                {
                    "severity": "high",
                    "title": f"TLS on {h}:{p}",
                    "description": str(info.get("error", "error")),
                    "evidence": info,
                }
            ]
        else:
            dl = info.get("days_left")
            sev = "high" if isinstance(dl, int) and dl < 7 else "medium" if isinstance(dl, int) and dl < 30 else "low"
            cn = (info.get("subject") or {}).get("commonName", "")
            findings = [
                {
                    "severity": sev,
                    "title": f"TLS cert for {h}:{p} — CN {cn or '—'}",
                    "description": f"Expires in ~{dl} day(s) after {info.get('not_after', '—')}",
                    "evidence": info,
                }
            ]
        await _persist_findings(db, uuid.UUID(job_id), findings)
        job.result_json = info
        await _set_status(db, uuid.UUID(job_id), "done")
        await db.commit()
    await publish(CHANNEL_RECON, {"job_id": job_id, "kind": "tls_cert", "count": len(findings)})
    return {"ok": bool(info.get("ok"))}


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


@celery_app.task(name="recon.dns")
def run_dns_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_dns(job_id, target, params or {}))


@celery_app.task(name="recon.httprobe")
def run_httprobe_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_httprobe(job_id, target, params or {}))


@celery_app.task(name="recon.http_headers")
def run_http_headers_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_http_headers(job_id, target, params or {}))


@celery_app.task(name="recon.tls_cert")
def run_tls_cert_job(job_id: str, target: str, params: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_run_tls_cert(job_id, target, params or {}))


@celery_app.task(name="recon.rescue")
def rescue_orphans() -> dict[str, int]:
    """Periodic + on-demand task: re-dispatch any recon job stuck in 'queued'.

    Triggered every minute via beat (see ``celery_app.beat_schedule``) and
    once on worker startup via the ``worker_ready`` signal handler.
    """
    from app.modules.recon.rescue import run_rescue_sync  # noqa: WPS433

    return run_rescue_sync()
