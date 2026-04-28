"""Audit Set-Cookie attributes (Secure / HttpOnly / SameSite / __Host-).

We deliberately use ``httpx.AsyncClient(follow_redirects=False)`` for the
initial request because many sites set their session cookies on the redirect
response itself. We then make a second pass with ``follow_redirects=True``
for any cookie set deeper in the chain.
"""
from __future__ import annotations

from typing import Any

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_USER_AGENT = "SentinelOps-Recon/1.0"


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse one Set-Cookie line into a structured dict."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return {}
    name_value, *attrs = parts
    if "=" in name_value:
        name, value = name_value.split("=", 1)
    else:
        name, value = name_value, ""
    out: dict[str, Any] = {
        "name": name.strip(),
        "value_truncated": value.strip()[:120],
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "max_age": None,
        "expires": None,
        "host_prefix": name.strip().lower().startswith("__host-"),
        "secure_prefix": name.strip().lower().startswith("__secure-"),
    }
    for a in attrs:
        a_low = a.lower()
        if a_low == "secure":
            out["secure"] = True
        elif a_low == "httponly":
            out["httponly"] = True
        elif a_low.startswith("samesite="):
            out["samesite"] = a.split("=", 1)[1].strip()
        elif a_low.startswith("domain="):
            out["domain"] = a.split("=", 1)[1].strip()
        elif a_low.startswith("path="):
            out["path"] = a.split("=", 1)[1].strip()
        elif a_low.startswith("max-age="):
            try:
                out["max_age"] = int(a.split("=", 1)[1].strip())
            except ValueError:
                out["max_age"] = a.split("=", 1)[1].strip()
        elif a_low.startswith("expires="):
            out["expires"] = a.split("=", 1)[1].strip()
    return out


def _score(cookie: dict[str, Any], on_https: bool) -> tuple[str, list[str]]:
    issues: list[str] = []
    if on_https and not cookie.get("secure"):
        issues.append("missing Secure (sent on HTTPS request)")
    if not cookie.get("httponly"):
        issues.append("missing HttpOnly (readable from JS)")
    samesite = (cookie.get("samesite") or "").lower()
    if not samesite:
        issues.append("missing SameSite (browser default may be Lax, but be explicit)")
    elif samesite == "none" and not cookie.get("secure"):
        issues.append("SameSite=None requires Secure")
    if cookie.get("host_prefix") and cookie.get("domain"):
        issues.append("__Host- prefix forbids Domain attribute")
    if cookie.get("secure_prefix") and not cookie.get("secure"):
        issues.append("__Secure- prefix requires Secure")
    severity = "high" if any("requires Secure" in s for s in issues) else (
        "medium" if len(issues) >= 2 else "low" if issues else "info"
    )
    return severity, issues


async def audit_cookies(target: str, *, https_only: bool = False) -> dict[str, Any]:
    t = (target or "").strip()
    if not t:
        return {"ok": False, "error": "empty target", "cookies": []}
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        try_urls: tuple[str, ...] = (t,)
    elif https_only:
        try_urls = (f"https://{t}/",)
    else:
        try_urls = (f"https://{t}/", f"http://{t}/")

    headers = {"User-Agent": _USER_AGENT}
    cookies_collected: list[dict[str, Any]] = []
    final_url: str | None = None
    final_https = False
    last_error: str | None = None

    for url in try_urls:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), verify=True, headers=headers) as nofw:
                hops = []
                cur = url
                for _ in range(6):
                    r = await nofw.get(cur)
                    hops.append(r)
                    if not (300 <= r.status_code < 400):
                        break
                    loc = r.headers.get("location")
                    if not loc:
                        break
                    cur = httpx.URL(cur).join(loc).human_repr()
                final_url = str(hops[-1].url)
                final_https = final_url.lower().startswith("https://")
                seen_keys: set[str] = set()
                for resp in hops:
                    for raw in resp.headers.get_list("set-cookie"):
                        parsed = _parse_set_cookie(raw)
                        if not parsed:
                            continue
                        key = (parsed.get("name", ""), parsed.get("path") or "/")
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        sev, issues = _score(parsed, final_https)
                        parsed["severity"] = sev
                        parsed["issues"] = issues
                        cookies_collected.append(parsed)
            break
        except httpx.RequestError as exc:
            last_error = str(exc)
            continue

    return {
        "ok": final_url is not None,
        "url": final_url,
        "on_https": final_https,
        "error": None if final_url else last_error,
        "cookies": cookies_collected,
        "summary": {
            "total": len(cookies_collected),
            "with_issues": sum(1 for c in cookies_collected if c.get("issues")),
            "high": sum(1 for c in cookies_collected if c.get("severity") == "high"),
        },
    }
