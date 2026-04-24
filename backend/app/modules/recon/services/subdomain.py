"""Async subdomain enumeration (DNS brute + Certificate Transparency)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

import dns.asyncresolver
import dns.exception
import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


DEFAULT_WORDLIST: list[str] = [
    "www", "mail", "ftp", "api", "admin", "dev", "staging", "beta",
    "portal", "vpn", "git", "gitlab", "jenkins", "ci", "build", "qa", "uat", "prod",
    "internal", "intranet", "extranet", "cdn", "static", "media", "img", "assets", "files",
    "download", "shop", "store", "blog", "news", "status", "monitor", "metrics", "grafana",
    "kibana", "prometheus", "auth", "sso", "login", "account", "my", "app", "apps", "web",
    "support", "help", "docs", "edge", "cache", "origin", "gateway", "proxy", "mx",
    "smtp", "pop", "imap", "ns", "ns1", "ns2", "dns", "autodiscover", "owa", "remote",
]


@dataclass(slots=True)
class SubdomainHit:
    name: str
    a_records: list[str]
    aaaa_records: list[str]
    source: str = "dns_brute"


async def _resolve(
    resolver: dns.asyncresolver.Resolver, fqdn: str, *, source: str = "dns_brute"
) -> SubdomainHit | None:
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
    return SubdomainHit(name=fqdn, a_records=a, aaaa_records=aaaa, source=source)


async def _crtsh_candidates(domain: str) -> list[str]:
    """Query the public Certificate Transparency log index (crt.sh) for issued
    certificates whose Subject / SAN contain ``%.domain``. Returns unique FQDNs
    under the input apex, excluding wildcards.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    candidates: set[str] = set()
    try:
        async with httpx.AsyncClient(
            timeout=max(settings.recon_timeout_seconds * 3, 15),
            headers={"User-Agent": "SentinelOps-Recon/1.0"},
        ) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.info("subdomain.crtsh.unavailable", domain=domain, error=str(exc))
        return []

    for item in data if isinstance(data, list) else []:
        for field in ("name_value", "common_name"):
            v = item.get(field)
            if not v:
                continue
            for raw in str(v).splitlines():
                name = raw.strip().lower().rstrip(".")
                if not name or "*" in name or " " in name:
                    continue
                if name == domain or name.endswith(f".{domain}"):
                    candidates.add(name)
    return sorted(candidates)


async def enumerate_subdomains(
    domain: str,
    wordlist: Iterable[str] | None = None,
    *,
    concurrency: int | None = None,
    include_ct: bool = True,
) -> list[SubdomainHit]:
    """Enumerate live subdomains under ``domain``.

    Combines DNS brute-force with Certificate Transparency (crt.sh). A name is
    only returned if it resolves (A or AAAA) from the worker's resolver.
    """
    words = list(wordlist) if wordlist else DEFAULT_WORDLIST
    semaphore = asyncio.Semaphore(concurrency or settings.recon_max_concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = settings.recon_timeout_seconds

    async def brute(prefix: str) -> SubdomainHit | None:
        async with semaphore:
            return await _resolve(resolver, f"{prefix}.{domain}", source="dns_brute")

    brute_task = asyncio.gather(*(brute(p) for p in words))
    ct_names: list[str] = await _crtsh_candidates(domain) if include_ct else []

    async def resolve_ct(name: str) -> SubdomainHit | None:
        async with semaphore:
            return await _resolve(resolver, name, source="ct_log")

    ct_task = asyncio.gather(*(resolve_ct(n) for n in ct_names))
    brute_results, ct_results = await asyncio.gather(brute_task, ct_task)

    seen: dict[str, SubdomainHit] = {}
    for r in [*brute_results, *ct_results]:
        if r is None:
            continue
        existing = seen.get(r.name)
        if existing is None:
            seen[r.name] = r
        else:
            for ip in r.a_records:
                if ip not in existing.a_records:
                    existing.a_records.append(ip)
            for ip6 in r.aaaa_records:
                if ip6 not in existing.aaaa_records:
                    existing.aaaa_records.append(ip6)
    hits = list(seen.values())
    log.info(
        "subdomain.scan.done",
        domain=domain,
        tried=len(words),
        ct_candidates=len(ct_names),
        found=len(hits),
    )
    return hits
