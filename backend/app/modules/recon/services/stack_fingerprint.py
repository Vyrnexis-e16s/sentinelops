"""Lightweight HTTP stack hints from headers + body (no third-party API)."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

_HEADER_SIGNALS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (r"^server$", re.compile(r"nginx", re.I), "Nginx (Server header)"),
    (r"^server$", re.compile(r"Apache|httpd", re.I), "Apache httpd (Server header)"),
    (r"^server$", re.compile(r"cloudflare|cf-ray", re.I), "Cloudflare edge"),
    (r"^server$", re.compile(r"Microsoft-IIS", re.I), "Microsoft IIS"),
    (r"^x-powered-by$", re.compile(r"PHP", re.I), "PHP (X-Powered-By)"),
    (r"^x-powered-by$", re.compile(r"Express", re.I), "Express.js (X-Powered-By)"),
    (r"^x-powered-by$", re.compile(r"ASP\.NET", re.I), "ASP.NET (X-Powered-By)"),
    (r"^x-generator$", re.compile(r"WordPress", re.I), "WordPress (X-Generator)"),
)

_BODY_SNIPPET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress paths in HTML"),
    (re.compile(r"react(?:root|dom)?", re.I), "Possible React bundle"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js (__NEXT_DATA__)"),
    (re.compile(r"litespeed", re.I), "LiteSpeed mention in body"),
    (re.compile(r"django", re.I), "Django mention"),
    (re.compile(r"laravel", re.I), "Laravel mention"),
)


def _origin_url(target: str) -> str:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return f"https://{t}"


async def fingerprint_url(
    target: str,
    *,
    path: str = "/",
    timeout: float | None = None,
) -> dict[str, Any]:
    """GET one URL and derive signals."""
    to = timeout or float(settings.recon_timeout_seconds)
    base = _origin_url(target)
    p = urlparse(base)
    origin = f"{p.scheme}://{p.netloc.split('@')[-1]}".rstrip("/")
    url = f"{origin}{path if path.startswith('/') else '/' + path}"
    async with httpx.AsyncClient(
        timeout=to,
        follow_redirects=True,
        headers={"User-Agent": "SentinelOps-Recon/1.0"},
    ) as client:
        try:
            r = await client.get(url)
        except httpx.HTTPError as exc:
            return {"ok": False, "url": url, "error": str(exc)}
    text = (r.text or "")[:24_000]
    lower_headers = {k.lower(): v for k, v in r.headers.items()}
    signals: list[str] = []
    for hk, pat, label in _HEADER_SIGNALS:
        for lk, lv in lower_headers.items():
            if re.match(hk, lk):
                if pat.search(f"{lv}"):
                    signals.append(label)
    for pat, label in _BODY_SNIPPET_PATTERNS:
        if pat.search(text):
            signals.append(label)
    seen: set[str] = set()
    uniq: list[str] = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return {
        "ok": True,
        "url": str(r.url),
        "status": r.status_code,
        "headers": lower_headers,
        "signals": uniq,
        "title_guess": _title(text),
    }


def _title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>([^<]{1,300})</title>", html, re.I)
    return m.group(1).strip() if m else None
