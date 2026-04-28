"""Probe http/https reachability; useful for “what is live” checks.

Each probe row is enriched with timing and byte-count fields so downstream
modules (e.g. the IDS flow-inference UI) can build a realistic NSL-KDD-style
feature record from real recon data instead of a hand-crafted example.
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_TITLE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I)
_USER_AGENT = "SentinelOps-Recon/1.0"


def _estimate_request_bytes(url: str, method: str = "GET") -> int:
    """Rough size of the request line + a small set of default headers we send.

    httpx doesn't expose serialised request bytes pre-flight; this is a stable
    lower bound that's good enough for a flow-feature heuristic.
    """
    try:
        request_line = f"{method} {url} HTTP/1.1\r\n"
        headers = (
            f"Host: \r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        return len(request_line.encode("utf-8", errors="ignore")) + len(
            headers.encode("utf-8", errors="ignore")
        )
    except Exception:  # noqa: BLE001
        return 200


async def probe(target: str, *, https_only: bool = False) -> list[dict[str, Any]]:
    t = (target or "").strip()
    if not t:
        return []
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        urls = [t]
    else:
        # Host[:port] or host/path — default: try HTTPS first (real TLS), then HTTP.
        if https_only:
            urls = [f"https://{t}/"]
        else:
            urls = [f"https://{t}/", f"http://{t}/"]

    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        verify=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        for url in urls:
            t0 = time.monotonic()
            try:
                r = await client.get(url)
                duration = max(time.monotonic() - t0, 0.0)
                body_len = len(r.content) if r.content is not None else 0
                title: str | None = None
                ct = (r.headers.get("content-type") or "").lower()
                if "html" in ct and r.text:
                    m = _TITLE.search(r.text[:32_000])
                    if m:
                        title = m.group(1).strip()[:500]
                is_https = str(r.url).lower().startswith("https://")
                hv = getattr(r, "http_version", None)
                out.append(
                    {
                        "url": str(r.url),
                        "method": "GET",
                        "https": is_https,
                        "http_version": str(hv) if hv is not None else "HTTP/1.1",
                        "status": r.status_code,
                        "server": r.headers.get("server"),
                        "content_type": r.headers.get("content-type"),
                        "title": title,
                        # IDS-flow friendly fields (NSL-KDD analogues for HTTP):
                        "request_bytes": _estimate_request_bytes(str(r.url)),
                        "response_bytes": body_len,
                        "duration_seconds": round(duration, 4),
                    }
                )
            except httpx.RequestError as exc:
                out.append({"url": url, "method": "GET", "error": str(exc), "ok": False})
            except Exception as exc:  # noqa: BLE001
                log.info("httprobe.unexpected", url=url, error=str(exc))
                out.append({"url": url, "method": "GET", "error": str(exc), "ok": False})
    return out
