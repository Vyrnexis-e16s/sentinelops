"""NVD 2.0 CVE lookup by CPE, cached in Redis for 24h.

Accepts three forms of input:

* Full CPE 2.3 URI (``cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*``) – sent as
  the NVD ``cpeName`` exact match.
* ``product``, ``product:version``, or ``vendor:product:version`` shortcut –
  expanded into a CPE 2.3 match string and sent as ``virtualMatchString`` so
  the NVD API performs partial matching with range semantics.

**Not supported as CPE input:** a bare FQDN such as ``example.com`` — use
``vendor:product:version`` or a full CPE; otherwise the worker short-circuits
with a hint finding.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

CACHE_TTL = 60 * 60 * 24  # 24h
CACHE_PREFIX = "recon:cve:"

_CPE_SAFE_RE = re.compile(r"[^a-zA-Z0-9_.\-]")
# Hostname with at least one dot, no : — distinguishes from vendor:product:ver
_FQDN_LIKE = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def is_bare_fqdn_not_cpe(raw: str) -> bool:
    """True for ``seekpious.com``-style input that is not a valid CPE shortcut."""
    t = raw.strip()
    if not t or t.startswith("cpe:") or t.startswith("cpe/") or ":" in t:
        return False
    return bool(_FQDN_LIKE.match(t))


def build_cpe_match(raw: str) -> tuple[str, str]:
    """Return (nvd_param_name, cpe_string).

    ``nvd_param_name`` is either ``cpeName`` for an exact match on a complete
    CPE or ``virtualMatchString`` for a shortcut that allows wildcards.
    """
    v = raw.strip()
    if v.startswith("cpe:2.3:"):
        return "cpeName", v

    parts = [_CPE_SAFE_RE.sub("", p) for p in v.split(":") if p]
    if not parts:
        raise ValueError("CPE input is empty.")
    if len(parts) == 1:
        vendor = product = parts[0]
        version = "*"
    elif len(parts) == 2:
        vendor = product = parts[0]
        version = parts[1]
    else:
        vendor, product, version = parts[0], parts[1], parts[2]
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return "virtualMatchString", cpe


async def _get_cache(redis: aioredis.Redis, key: str) -> dict[str, Any] | None:
    raw = await redis.get(CACHE_PREFIX + key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def _set_cache(redis: aioredis.Redis, key: str, value: dict[str, Any]) -> None:
    try:
        await redis.setex(CACHE_PREFIX + key, CACHE_TTL, json.dumps(value).encode("utf-8"))
    except (OSError, TypeError) as exc:
        log.warning("cve.cache.set_failed", error=str(exc))


async def query_cves(
    cpe_match: str, *, redis: aioredis.Redis, limit: int = 50
) -> dict[str, Any]:
    """Query NVD by CPE string or ``product:version`` shortcut."""
    try:
        param_name, cpe_string = build_cpe_match(cpe_match)
    except ValueError as exc:
        return {"vulnerabilities": [], "error": str(exc)}

    cache_key = f"{param_name}:{cpe_string}:{limit}"
    cached = await _get_cache(redis, cache_key)
    if cached is not None:
        log.info("cve.cache.hit", cpe=cpe_string)
        return cached

    params: dict[str, str] = {param_name: cpe_string, "resultsPerPage": str(limit)}
    if settings.nvd_api_key.strip():
        params["apiKey"] = settings.nvd_api_key.strip()

    timeout = httpx.Timeout(
        connect=20.0,
        read=settings.nvd_request_timeout,
        write=20.0,
        pool=20.0,
    )
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": "SentinelOps-Recon/1.0"},
    ) as client:
        try:
            resp = await client.get(settings.nvd_api_base, params=params)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("cve.nvd.error", cpe=cpe_string, error=str(exc))
            return {"vulnerabilities": [], "error": str(exc), "cpe": cpe_string}
        try:
            data: dict[str, Any] = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("cve.nvd.json", cpe=cpe_string, error=str(exc))
            return {
                "vulnerabilities": [],
                "error": f"NVD did not return JSON: {exc}",
                "cpe": cpe_string,
            }

    rows: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", []):
        cve_block = v.get("cve") or {}
        cve_id = cve_block.get("id")
        if not cve_id:
            continue
        rows.append(
            {
                "cve_id": cve_id,
                "summary": next(
                    (d.get("value") for d in cve_block.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                ),
                "severity": _severity_from_metrics(cve_block.get("metrics", {})),
            }
        )
    summary = {
        "cpe": cpe_string,
        "match_type": param_name,
        "total_results": data.get("totalResults", 0),
        "vulnerabilities": rows,
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
            if isinstance(score, (int, float)):
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
    return "unknown"
