"""Subdomain takeover detector.

For each candidate name (or each live subdomain produced by an earlier
``recon.subdomain`` job), follow the CNAME chain and try to fetch the apex
HTTP(S) response. If the apex resolves to a third-party service whose tenant
has been deprovisioned (Heroku / GitHub Pages / S3 / Azure / Fastly / …) the
HTTP body usually contains a known fingerprint string (e.g. "There's nothing
here yet" for GitHub Pages, "NoSuchBucket" for AWS S3). We score the result
as ``vulnerable``, ``review``, or ``ok`` and surface the CNAME chain so an
analyst can confirm.

The fingerprint table is intentionally small and conservative — the goal is
zero false positives at the cost of some false negatives. Add new entries
in ``TAKEOVER_FINGERPRINTS`` as new providers become known.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver
import httpx

from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class TakeoverFingerprint:
    provider: str
    cname_suffixes: tuple[str, ...]
    body_markers: tuple[str, ...]
    severity: str = "high"


TAKEOVER_FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    TakeoverFingerprint(
        provider="GitHub Pages",
        cname_suffixes=("github.io", "github.map.fastly.net"),
        body_markers=("There isn't a GitHub Pages site here.", "There's nothing here yet"),
    ),
    TakeoverFingerprint(
        provider="Heroku",
        cname_suffixes=("herokuapp.com", "herokudns.com"),
        body_markers=("No such app", "herokucdn.com/error-pages/no-such-app.html"),
    ),
    TakeoverFingerprint(
        provider="AWS S3 (static site)",
        cname_suffixes=("s3.amazonaws.com", "s3-website", "amazonaws.com"),
        body_markers=("NoSuchBucket", "The specified bucket does not exist"),
    ),
    TakeoverFingerprint(
        provider="Azure (cloudapp / azurewebsites)",
        cname_suffixes=(
            "cloudapp.net",
            "cloudapp.azure.com",
            "azurewebsites.net",
            "trafficmanager.net",
        ),
        body_markers=("404 Web Site not found", "Error 404 - Web app not found"),
    ),
    TakeoverFingerprint(
        provider="Fastly",
        cname_suffixes=("fastly.net",),
        body_markers=("Fastly error: unknown domain",),
    ),
    TakeoverFingerprint(
        provider="Shopify",
        cname_suffixes=("myshopify.com",),
        body_markers=("Sorry, this shop is currently unavailable.",),
        severity="medium",
    ),
    TakeoverFingerprint(
        provider="Tumblr",
        cname_suffixes=("tumblr.com",),
        body_markers=("There's nothing here.", "Whatever you were looking for doesn't currently exist"),
    ),
    TakeoverFingerprint(
        provider="Bitbucket",
        cname_suffixes=("bitbucket.io",),
        body_markers=("Repository not found",),
    ),
    TakeoverFingerprint(
        provider="Surge.sh",
        cname_suffixes=("surge.sh",),
        body_markers=("project not found",),
    ),
    TakeoverFingerprint(
        provider="Pantheon",
        cname_suffixes=("pantheonsite.io",),
        body_markers=("The gods are wise, but do not know of the site which you seek.",),
    ),
    TakeoverFingerprint(
        provider="Unbounce",
        cname_suffixes=("unbouncepages.com",),
        body_markers=("The requested URL was not found on this server.",),
        severity="medium",
    ),
    TakeoverFingerprint(
        provider="Zendesk",
        cname_suffixes=("zendesk.com",),
        body_markers=("Help Center Closed",),
        severity="medium",
    ),
)


def _resolve_cname_chain(name: str, max_depth: int = 6) -> list[str]:
    chain: list[str] = []
    current = name.strip().rstrip(".")
    for _ in range(max_depth):
        try:
            answer = dns.resolver.resolve(current, "CNAME", lifetime=6.0, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return chain
        except dns.exception.DNSException:
            return chain
        nxt = str(answer[0].target).rstrip(".")
        if not nxt or nxt == current:
            return chain
        chain.append(nxt)
        current = nxt
    return chain


def _classify(chain: list[str], body: str) -> tuple[str, str | None, str]:
    body_lower = body.lower() if body else ""
    for fp in TAKEOVER_FINGERPRINTS:
        suffix_match = any(
            link.lower().endswith(suffix.lower())
            for link in chain
            for suffix in fp.cname_suffixes
        )
        if not suffix_match:
            continue
        if any(marker.lower() in body_lower for marker in fp.body_markers):
            return ("vulnerable", fp.provider, fp.severity)
        return ("review", fp.provider, "low")
    return ("ok", None, "info")


async def _check_one(client: httpx.AsyncClient, name: str) -> dict[str, Any]:
    chain = await asyncio.to_thread(_resolve_cname_chain, name)
    body = ""
    status: int | None = None
    err: str | None = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{name}/"
        try:
            r = await client.get(url)
            status = r.status_code
            body = r.text[:32_000] if r.text else ""
            break
        except httpx.RequestError as exc:
            err = str(exc)
            continue
    classification, provider, severity = _classify(chain, body)
    return {
        "name": name,
        "cname_chain": chain,
        "http_status": status,
        "provider_match": provider,
        "classification": classification,
        "severity": severity,
        "error": err if status is None else None,
    }


async def detect_takeovers(
    targets: list[str], *, concurrency: int = 8
) -> list[dict[str, Any]]:
    cleaned = [t.strip().rstrip(".") for t in targets if t and t.strip()]
    if not cleaned:
        return []
    sem = asyncio.Semaphore(max(1, min(concurrency, 32)))
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(12.0),
        verify=True,
        headers={"User-Agent": "SentinelOps-Takeover/1.0"},
    ) as client:

        async def runner(n: str) -> dict[str, Any]:
            async with sem:
                try:
                    return await _check_one(client, n)
                except Exception as exc:  # noqa: BLE001
                    log.info("takeover.unexpected", name=n, error=str(exc))
                    return {"name": n, "classification": "error", "error": str(exc)}

        return list(await asyncio.gather(*(runner(n) for n in cleaned)))
