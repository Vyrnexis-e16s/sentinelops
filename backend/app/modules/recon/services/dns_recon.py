"""Async-friendly DNS record collection (A/AAAA/MX/NS/TXT) via dnspython."""
from __future__ import annotations

import asyncio
from typing import Any

import dns.exception
import dns.resolver
from app.core.logging import get_logger

log = get_logger(__name__)


def _sync_collect(name: str) -> dict[str, Any]:
    name = name.strip().rstrip(".")
    res: dict[str, Any] = {"name": name, "records": {}}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        key = rtype.lower()
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=8.0, search=False)
            res["records"][key] = [a.to_text() for a in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            res["records"][key] = []
        except dns.exception.DNSException as exc:
            log.info("dns.resolve.partial", name=name, rtype=rtype, error=str(exc))
            res["records"][key] = []
    return res


async def collect_records(name: str) -> dict[str, Any]:
    return await asyncio.to_thread(_sync_collect, name)
