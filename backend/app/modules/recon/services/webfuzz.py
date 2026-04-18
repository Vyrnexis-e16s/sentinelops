"""Async aiohttp path fuzzer."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

import aiohttp

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


# Curated 100-path common wordlist.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin", "admin/", "administrator", "login", "signin", "signup", "register",
    "dashboard", "console", "portal", "manage", "manager", "cpanel", "webmail",
    "wp-admin", "wp-admin/", "wp-login.php", "xmlrpc.php", "wp-content", "wp-includes",
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD", ".git/index",
    ".svn/entries", ".hg/hgrc", ".DS_Store", "robots.txt", "sitemap.xml", "humans.txt",
    "security.txt", ".well-known/security.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    "backup", "backups", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "database.sql",
    "config", "config.php", "config.yml", "config.yaml", "config.json", "settings.py",
    "web.config", "phpinfo.php", "info.php", "test.php", "api", "api/", "api/v1",
    "api/v1/users", "api/v2", "swagger", "swagger.json", "swagger-ui", "openapi.json",
    "graphql", "graphiql", "actuator", "actuator/health", "actuator/env", "metrics",
    "health", "status", "ping", "server-status", "server-info", "solr", "jenkins", "kibana",
    "grafana", "prometheus", "console/", "adminer.php", "phpmyadmin", "pma", "sqladmin",
    "files", "uploads", "upload", "images", "media", "assets", "static", "public",
    "old", "new", "tmp", "temp", "logs", "log", "error_log", "debug", "install",
    "setup", "node_modules", "vendor", "composer.json", "package.json",
)


@dataclass(slots=True)
class FuzzHit:
    path: str
    status: int
    content_length: int | None
    content_type: str | None


async def _probe(
    session: aiohttp.ClientSession, base: str, path: str, sem: asyncio.Semaphore, timeout: float
) -> FuzzHit | None:
    url = base.rstrip("/") + "/" + path.lstrip("/")
    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False
            ) as resp:
                if resp.status in {404, 400, 501}:
                    return None
                return FuzzHit(
                    path=path,
                    status=resp.status,
                    content_length=(
                        int(resp.headers["Content-Length"])
                        if "Content-Length" in resp.headers
                        else None
                    ),
                    content_type=resp.headers.get("Content-Type"),
                )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None


async def fuzz_paths(
    base_url: str,
    wordlist: Iterable[str] | None = None,
    *,
    concurrency: int | None = None,
    interesting_statuses: tuple[int, ...] = (200, 201, 301, 302, 401, 403, 500),
) -> list[FuzzHit]:
    words = list(wordlist) if wordlist else list(DEFAULT_WORDLIST)
    sem = asyncio.Semaphore(concurrency or settings.recon_max_concurrency)
    timeout = float(settings.recon_timeout_seconds)
    headers = {"User-Agent": "SentinelOps-Recon/0.1"}
    async with aiohttp.ClientSession(headers=headers) as session:
        results = await asyncio.gather(
            *(_probe(session, base_url, w, sem, timeout) for w in words)
        )
    hits = [r for r in results if r is not None and r.status in interesting_statuses]
    log.info("webfuzz.done", base=base_url, tested=len(words), hits=len(hits))
    return hits
