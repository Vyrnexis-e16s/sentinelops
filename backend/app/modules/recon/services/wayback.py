"""Pull historical URLs for a host from the Wayback Machine CDX API.

Useful as seed material for ``recon.webfuzz`` — historical URLs often expose
endpoints / paths that are no longer linked from the current site but still
respond. We deduplicate by path-only by default so the seed list is short
even when archive.org has thousands of snapshots.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_USER_AGENT = "SentinelOps-Recon/1.0"
_CDX_BASE = "https://web.archive.org/cdx/search/cdx"


async def fetch_wayback_urls(
    target: str,
    *,
    limit: int = 200,
    only_status_2xx: bool = False,
    dedupe_by_path: bool = True,
) -> dict[str, Any]:
    t = (target or "").strip()
    if not t:
        return {"ok": False, "error": "empty target", "urls": []}
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        host = urlparse(t).netloc or t
    else:
        host = t

    params: dict[str, Any] = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(max(1, min(int(limit), 5000))),
    }
    if only_status_2xx:
        params["filter"] = "statuscode:2.."

    rows: list[list[str]] = []
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            verify=True,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            r = await client.get(_CDX_BASE, params=params)
            if r.status_code >= 400:
                return {"ok": False, "error": f"CDX HTTP {r.status_code}", "urls": []}
            data = r.json()
            if isinstance(data, list):
                rows = data
    except httpx.RequestError as exc:
        return {"ok": False, "error": f"network: {exc}", "urls": []}
    except ValueError as exc:
        return {"ok": False, "error": f"bad CDX JSON: {exc}", "urls": []}

    urls: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    if rows and rows[0] and isinstance(rows[0], list) and rows[0][:1] == ["timestamp"]:
        rows = rows[1:]
    for row in rows:
        if not isinstance(row, list) or len(row) < 2:
            continue
        timestamp, original, *rest = row
        status = rest[0] if rest else None
        mimetype = rest[1] if len(rest) > 1 else None
        try:
            parsed = urlparse(original)
        except ValueError:
            continue
        path = parsed.path or "/"
        if dedupe_by_path:
            key = path
        else:
            key = original
        if key in seen_keys:
            continue
        seen_keys.add(key)
        urls.append(
            {
                "timestamp": timestamp,
                "url": original,
                "path": path,
                "status": status,
                "mime": mimetype,
            }
        )
    return {
        "ok": True,
        "host": host,
        "source": "web.archive.org/cdx",
        "count": len(urls),
        "urls": urls,
    }
