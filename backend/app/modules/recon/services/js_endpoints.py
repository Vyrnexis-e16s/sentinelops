"""Extract API endpoints from a site's HTML and JS bundles.

Process:
  1. Fetch the homepage (or a user-supplied URL).
  2. Walk every ``<script src="...">`` tag (capped at ``max_scripts``).
  3. Download each JS body (capped at ``per_script_bytes``).
  4. Run a small set of regexes to surface ``/api/*``, ``/v1/*``, fetch(),
     axios.<method>(), and bare absolute URLs.

This is intentionally a heuristic scanner — modern bundlers minify and
template URLs (e.g. ``API_BASE+"/users/"+id``), so we can't enumerate
every dynamic path. The goal is to surface a high-value seed list that an
analyst (or the ``recon.webfuzz`` job) can iterate on.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_USER_AGENT = "SentinelOps-Recon/1.0"
_SCRIPT_TAG = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)

_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[\"'`](\/api\/[a-zA-Z0-9_\-\/\.\:]{1,160})[\"'`]"),
    re.compile(r"[\"'`](\/v\d+\/[a-zA-Z0-9_\-\/\.\:]{1,160})[\"'`]"),
    re.compile(r"[\"'`](\/graphql[a-zA-Z0-9_\-\/\.\:]*)[\"'`]"),
    re.compile(r"fetch\([\"'`]([^\"'`]{1,300})[\"'`]"),
    re.compile(r"axios\.(?:get|post|put|delete|patch)\([\"'`]([^\"'`]{1,300})[\"'`]"),
    re.compile(r"[\"'`](https?://[a-zA-Z0-9_\-\.\:/]{4,200}/api/[a-zA-Z0-9_\-\/\.\:]{1,160})[\"'`]"),
)


def _filter_paths(found: list[str], same_origin: str | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in found:
        v = raw.strip()
        if not v:
            continue
        if v.startswith("http://") or v.startswith("https://"):
            try:
                parsed = urlparse(v)
            except ValueError:
                continue
            if same_origin and parsed.netloc and parsed.netloc != same_origin:
                continue
            v = parsed.path or "/"
        if not v.startswith("/"):
            continue
        if v.startswith("//") or v.startswith("/.."):
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


async def extract_endpoints(
    target: str,
    *,
    max_scripts: int = 8,
    per_script_bytes: int = 1_000_000,
) -> dict[str, Any]:
    t = (target or "").strip()
    if not t:
        return {"ok": False, "error": "empty target", "paths": []}
    if not (t.lower().startswith("http://") or t.lower().startswith("https://")):
        t = f"https://{t}/"
    parsed = urlparse(t)
    same_origin = parsed.netloc

    paths_total: list[str] = []
    scripts_seen: list[str] = []
    scripts_failed: list[dict[str, str]] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(20.0),
        verify=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        try:
            html_resp = await client.get(t)
        except httpx.RequestError as exc:
            return {"ok": False, "error": f"failed to fetch HTML: {exc}", "paths": []}

        html_text = html_resp.text or ""
        for pat in _PATH_PATTERNS:
            paths_total.extend(pat.findall(html_text))

        script_srcs = _SCRIPT_TAG.findall(html_text)[:max_scripts]
        for raw_src in script_srcs:
            absolute = urljoin(t, raw_src)
            scripts_seen.append(absolute)
            try:
                jr = await client.get(absolute)
                if jr.status_code >= 400 or not jr.text:
                    scripts_failed.append({"url": absolute, "error": f"status {jr.status_code}"})
                    continue
                body = jr.text[:per_script_bytes]
                for pat in _PATH_PATTERNS:
                    paths_total.extend(pat.findall(body))
            except httpx.RequestError as exc:
                scripts_failed.append({"url": absolute, "error": str(exc)})

    paths = _filter_paths(paths_total, same_origin)
    return {
        "ok": True,
        "url": t,
        "scripts_seen": scripts_seen,
        "scripts_failed": scripts_failed,
        "raw_match_count": len(paths_total),
        "paths": paths,
    }
