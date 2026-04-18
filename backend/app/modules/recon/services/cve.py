"""NVD 2.0 CVE lookup by CPE, cached in Redis for 24h."""
from __future__ import annotations

import json
from typing import Any

import httpx
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

CACHE_TTL = 60 * 60 * 24  # 24h
CACHE_PREFIX = "recon:cve:"


async def _get_cache(redis: aioredis.Redis, key: str) -> dict[str, Any] | None:
    raw = await redis.get(CACHE_PREFIX + key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def _set_cache(redis: aioredis.Redis, key: str, value: dict[str, Any]) -> None:
    await redis.setex(CACHE_PREFIX + key, CACHE_TTL, json.dumps(value).encode("utf-8"))


async def query_cves(
    cpe_match: str, *, redis: aioredis.Redis, limit: int = 50
) -> dict[str, Any]:
    """Query NVD by CPE match string. Returns {"vulnerabilities": [...]}."""
    cache_key = f"cpe:{cpe_match}:{limit}"
    cached = await _get_cache(redis, cache_key)
    if cached is not None:
        log.info("cve.cache.hit", cpe=cpe_match)
        return cached

    params = {"cpeName": cpe_match, "resultsPerPage": str(limit)}
    async with httpx.AsyncClient(timeout=settings.recon_timeout_seconds * 3) as client:
        try:
            resp = await client.get(settings.nvd_api_base, params=params)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("cve.nvd.error", cpe=cpe_match, error=str(exc))
            return {"vulnerabilities": [], "error": str(exc)}

    data: dict[str, Any] = resp.json()
    summary = {
        "total_results": data.get("totalResults", 0),
        "vulnerabilities": [
            {
                "cve_id": v.get("cve", {}).get("id"),
                "summary": next(
                    (d.get("value") for d in v.get("cve", {}).get("descriptions", [])
                     if d.get("lang") == "en"),
                    "",
                ),
                "severity": _severity_from_metrics(v.get("cve", {}).get("metrics", {})),
            }
            for v in data.get("vulnerabilities", [])
        ],
    }
    await _set_cache(redis, cache_key, summary)
    return summary


def _severity_from_metrics(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            base = items[0].get("cvssData", {})
            sev = base.get("baseSeverity") or items[0].get("baseSeverity")
            if sev:
                return str(sev).lower()
            score = base.get("baseScore")
            if isinstance(score, int | float):
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
    return "unknown"
