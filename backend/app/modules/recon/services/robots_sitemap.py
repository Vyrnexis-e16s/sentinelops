"""Fetch robots.txt + sitemap.xml and emit a list of paths.

The output of this service is meant to be fed straight into ``recon.webfuzz``
or any path-aware scan: every ``Disallow:`` rule is exactly the kind of path
operators don't want crawled, which often correlates with sensitive
admin/API endpoints. Sitemap entries supply a high-quality real URL list.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.core.logging import get_logger

log = get_logger(__name__)

_DISALLOW = re.compile(r"^\s*disallow\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_ALLOW = re.compile(r"^\s*allow\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_SITEMAP_DIRECTIVE = re.compile(r"^\s*sitemap\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_USER_AGENT = "SentinelOps-Recon/1.0"


def _normalise_base(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        parsed = urlparse(t)
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{t}"


def _parse_sitemap_xml(body: bytes) -> tuple[list[str], list[str]]:
    """Return (urls, child_sitemap_urls)."""
    urls: list[str] = []
    children: list[str] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return urls, children
    tag_lower = root.tag.lower()
    if tag_lower.endswith("sitemapindex"):
        for sm in root.iter():
            if sm.tag.lower().endswith("loc") and sm.text:
                children.append(sm.text.strip())
    else:
        for url in root.iter():
            if url.tag.lower().endswith("loc") and url.text:
                urls.append(url.text.strip())
    return urls, children


async def collect(target: str, *, max_paths: int = 250, max_sitemaps: int = 5) -> dict[str, Any]:
    base = _normalise_base(target)
    if not base:
        return {"ok": False, "error": "empty target", "robots": {}, "paths": [], "sitemap_urls": []}

    robots_url = urljoin(base + "/", "robots.txt")
    disallow: list[str] = []
    allow: list[str] = []
    sitemap_decls: list[str] = []
    sitemap_urls: list[str] = []
    visited: set[str] = set()

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        verify=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        robots_status: int | None = None
        robots_text: str = ""
        try:
            r = await client.get(robots_url)
            robots_status = r.status_code
            if 200 <= r.status_code < 400 and r.text:
                robots_text = r.text[:64_000]
                disallow = [m.strip() for m in _DISALLOW.findall(robots_text) if m.strip() and m.strip() != "/"]
                allow = [m.strip() for m in _ALLOW.findall(robots_text) if m.strip()]
                sitemap_decls = [m.strip() for m in _SITEMAP_DIRECTIVE.findall(robots_text)]
        except httpx.RequestError as exc:
            log.info("robots.fetch_failed", url=robots_url, error=str(exc))

        candidates = list(sitemap_decls) or [urljoin(base + "/", "sitemap.xml")]
        seen_paths: set[str] = set()
        queue: list[str] = list(dict.fromkeys(candidates))
        while queue and len(visited) < max_sitemaps:
            sm_url = queue.pop(0)
            if sm_url in visited:
                continue
            visited.add(sm_url)
            try:
                resp = await client.get(sm_url)
                if not (200 <= resp.status_code < 400) or not resp.content:
                    continue
                urls, children = _parse_sitemap_xml(resp.content)
                for u in urls:
                    if u not in seen_paths:
                        seen_paths.add(u)
                        sitemap_urls.append(u)
                    if len(sitemap_urls) >= max_paths:
                        break
                if len(sitemap_urls) < max_paths:
                    queue.extend(c for c in children if c not in visited)
            except httpx.RequestError as exc:
                log.info("sitemap.fetch_failed", url=sm_url, error=str(exc))

    return {
        "ok": True,
        "base": base,
        "robots_url": robots_url,
        "robots_status": robots_status,
        "robots_text_len": len(robots_text),
        "disallow": disallow[:max_paths],
        "allow": allow[:max_paths],
        "sitemap_declarations": sitemap_decls,
        "sitemap_urls": sitemap_urls[:max_paths],
        "sitemaps_visited": list(visited),
    }
