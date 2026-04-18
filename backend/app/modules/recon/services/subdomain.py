"""Async subdomain enumeration using dnspython."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

import dns.asyncresolver
import dns.exception

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


DEFAULT_WORDLIST: list[str] = [
    "www", "mail", "ftp", "api", "admin", "dev", "staging", "test", "beta", "demo",
    "portal", "vpn", "git", "gitlab", "jenkins", "ci", "build", "qa", "uat", "prod",
    "internal", "intranet", "extranet", "cdn", "static", "media", "img", "assets", "files",
    "download", "shop", "store", "blog", "news", "status", "monitor", "metrics", "grafana",
    "kibana", "prometheus", "auth", "sso", "login", "account", "my", "app", "apps", "web",
    "support",
]


@dataclass(slots=True)
class SubdomainHit:
    name: str
    a_records: list[str]
    aaaa_records: list[str]


async def _resolve(resolver: dns.asyncresolver.Resolver, fqdn: str) -> SubdomainHit | None:
    a: list[str] = []
    aaaa: list[str] = []
    try:
        ans = await resolver.resolve(fqdn, "A", lifetime=settings.recon_timeout_seconds)
        a = [r.to_text() for r in ans]
    except (dns.exception.DNSException, asyncio.TimeoutError):
        pass
    try:
        ans = await resolver.resolve(fqdn, "AAAA", lifetime=settings.recon_timeout_seconds)
        aaaa = [r.to_text() for r in ans]
    except (dns.exception.DNSException, asyncio.TimeoutError):
        pass
    if not a and not aaaa:
        return None
    return SubdomainHit(name=fqdn, a_records=a, aaaa_records=aaaa)


async def enumerate_subdomains(
    domain: str,
    wordlist: Iterable[str] | None = None,
    *,
    concurrency: int | None = None,
) -> list[SubdomainHit]:
    """Resolve `prefix.domain` for each prefix in `wordlist`."""
    words = list(wordlist) if wordlist else DEFAULT_WORDLIST
    semaphore = asyncio.Semaphore(concurrency or settings.recon_max_concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = settings.recon_timeout_seconds

    async def bounded(prefix: str) -> SubdomainHit | None:
        async with semaphore:
            return await _resolve(resolver, f"{prefix}.{domain}")

    results = await asyncio.gather(*(bounded(p) for p in words))
    hits = [r for r in results if r is not None]
    log.info("subdomain.scan.done", domain=domain, tried=len(words), found=len(hits))
    return hits
