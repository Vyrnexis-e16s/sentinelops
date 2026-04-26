"""Fetch first successful response and score common security response headers."""
from __future__ import annotations

from typing import Any

import httpx

_SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("strict-transport-security", "HSTS", "Enforce HTTPS in browsers"),
    ("content-security-policy", "CSP", "Restrict script/inline content"),
    ("x-frame-options", "Clickjacking (X-Frame-Options)", "Disallow unwanted framing"),
    ("x-content-type-options", "MIME sniffing (nosniff)", "Reduce drive-by content confusion"),
    ("referrer-policy", "Referrer policy", "Limit referrer leakage"),
    ("permissions-policy", "Permissions policy", "Limit powerful browser features"),
    ("cross-origin-opener-policy", "Cross-origin isolation (COOP)", "Process isolation for browsing context"),
    ("cross-origin-resource-policy", "CORP", "Resource isolation from other origins"),
)


async def check_security_headers(target: str, *, https_only: bool = False) -> dict[str, Any]:
    t = (target or "").strip()
    if not t:
        return {"ok": False, "error": "empty target", "url": None, "headers": {}}
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        try_urls: tuple[str, ...] = (t,)
    elif https_only:
        try_urls = (f"https://{t}/",)
    else:
        try_urls = (f"https://{t}/", f"http://{t}/")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        verify=True,
        headers={"User-Agent": "SentinelOps-Recon/1.0"},
    ) as client:
        last_error: str | None = None
        for url in try_urls:
            try:
                r = await client.get(url)
                lower = {k.lower(): v for k, v in r.headers.items()}
                found: dict[str, str] = {}
                missing: list[str] = []
                for hkey, label, _why in _SECURITY_HEADERS:
                    if hkey in lower:
                        found[label] = lower[hkey][:200]
                    else:
                        missing.append(label)
                u = str(r.url)
                return {
                    "ok": True,
                    "url": u,
                    "https": u.lower().startswith("https://"),
                    "https_only_mode": https_only,
                    "status": r.status_code,
                    "headers_found": found,
                    "headers_missing": missing,
                    "server": r.headers.get("server"),
                }
            except httpx.RequestError as exc:
                last_error = str(exc)
        return {"ok": False, "error": last_error or "no response", "url": try_urls[0]}
