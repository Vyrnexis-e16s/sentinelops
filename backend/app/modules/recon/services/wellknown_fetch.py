"""Fetch security.txt, robots.txt, and related well-known paths (read-only HTTP)."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

DEFAULT_PATHS: tuple[tuple[str, str], ...] = (
    ("/.well-known/security.txt", "RFC 9116 security contact"),
    ("/security.txt", "security.txt (root)"),
    ("/robots.txt", "robots.txt"),
    ("/.well-known/change-password", "change-password well-known (URL)"),
)


def _base_urls_for_target(target: str) -> list[str]:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        p = urlparse(t)
        origin = f"{p.scheme}://{p.netloc.split('@')[-1]}"
        return [origin.rstrip("/")]
    # Prefer HTTPS then HTTP
    return [f"https://{t}", f"http://{t}"]


async def probe_well_known(
    target: str,
    paths: list[str] | None = None,
    *,
    timeout: float | None = None,
) -> list[dict[str, Any]]:
    """GET each path on first reachable origin; returns one row per path with status and snippet."""
    to = timeout or float(settings.recon_timeout_seconds)
    spec = paths if paths else [p[0] for p in DEFAULT_PATHS]
    labels = {p[0]: p[1] for p in DEFAULT_PATHS}
    bases = _base_urls_for_target(target)
    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=to,
        follow_redirects=True,
        headers={"User-Agent": "SentinelOps-Recon/1.0"},
    ) as client:
        for path in spec:
            got: dict[str, Any] | None = None
            for base in bases:
                url = f"{base.rstrip('/')}{path if path.startswith('/') else '/' + path}"
                try:
                    r = await client.get(url)
                    body = (r.text or "")[:2000]
                    got = {
                        "path": path,
                        "label": labels.get(path, path),
                        "url": str(r.url),
                        "status": r.status_code,
                        "content_type": r.headers.get("content-type", ""),
                        "snippet": body.replace("\r", " ")[:1200],
                    }
                    break
                except httpx.HTTPError as exc:
                    got = {
                        "path": path,
                        "label": labels.get(path, path),
                        "url": url,
                        "error": str(exc),
                    }
            if got:
                out.append(got)
    return out
