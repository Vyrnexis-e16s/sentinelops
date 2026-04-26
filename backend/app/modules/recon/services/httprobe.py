"""Probe http/https reachability; useful for “what is live” checks."""
from __future__ import annotations

import re
from typing import Any

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_TITLE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I)


async def probe(target: str) -> list[dict[str, Any]]:
    t = (target or "").strip()
    if not t:
        return []
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        urls = [t]
    else:
        # Host[:port] or host/path — use as netloc
        urls = [f"https://{t}/", f"http://{t}/"]

    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        verify=True,
        headers={"User-Agent": "SentinelOps-Recon/1.0"},
    ) as client:
        for url in urls:
            try:
                r = await client.get(url)
                title: str | None = None
                ct = (r.headers.get("content-type") or "").lower()
                if "html" in ct and r.text:
                    m = _TITLE.search(r.text[:32_000])
                    if m:
                        title = m.group(1).strip()[:500]
                out.append(
                    {
                        "url": str(r.url),
                        "status": r.status_code,
                        "server": r.headers.get("server"),
                        "content_type": r.headers.get("content-type"),
                        "title": title,
                    }
                )
            except httpx.RequestError as exc:
                out.append({"url": url, "error": str(exc), "ok": False})
            except Exception as exc:  # noqa: BLE001
                log.info("httprobe.unexpected", url=url, error=str(exc))
                out.append({"url": url, "error": str(exc), "ok": False})
    return out
