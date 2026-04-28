"""DNS zone-transfer (AXFR) probe.

A zone transfer is supposed to happen between authoritative name servers, not
to arbitrary clients. When a name server is misconfigured to allow AXFR from
the public Internet it leaks the entire zone — every record, including
internal/staging hostnames. This module attempts an AXFR against each
authoritative NS for the supplied domain and records:

* whether the transfer was refused / timed out (the safe / expected case),
* whether records were returned (the loud / vulnerable case), and
* a sample of the records so an operator can confirm.

We deliberately cap the captured record set to keep the result_json small.
"""
from __future__ import annotations

import asyncio
from typing import Any

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from app.core.logging import get_logger

log = get_logger(__name__)


def _list_nameservers(domain: str) -> list[str]:
    try:
        answer = dns.resolver.resolve(domain, "NS", lifetime=8.0, search=False)
        return [str(rdata.target).rstrip(".") for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        log.info("axfr.ns_lookup_failed", domain=domain, error=str(exc))
        return []


def _try_axfr_sync(domain: str, ns: str, *, timeout: float = 8.0, max_records: int = 50) -> dict[str, Any]:
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout, lifetime=timeout))
    except dns.exception.FormError:
        return {"ns": ns, "ok": False, "error": "form_error_or_refused", "records": []}
    except (TimeoutError, dns.exception.Timeout):
        return {"ns": ns, "ok": False, "error": "timeout", "records": []}
    except (ConnectionRefusedError, OSError) as exc:
        return {"ns": ns, "ok": False, "error": f"socket: {exc}", "records": []}
    except Exception as exc:  # noqa: BLE001
        return {"ns": ns, "ok": False, "error": f"{type(exc).__name__}: {exc}", "records": []}
    records: list[str] = []
    for name, _ttl, rdata in zone.iterate_rdatas():
        records.append(f"{name} {rdata.rdtype.name} {rdata}")
        if len(records) >= max_records:
            break
    return {"ns": ns, "ok": True, "error": None, "records": records, "leaked": True}


async def probe_axfr(domain: str) -> dict[str, Any]:
    d = (domain or "").strip().rstrip(".")
    if not d:
        return {"domain": "", "nameservers": [], "results": [], "any_leak": False}
    nameservers = await asyncio.to_thread(_list_nameservers, d)
    if not nameservers:
        return {
            "domain": d,
            "nameservers": [],
            "results": [],
            "any_leak": False,
            "error": "no NS records found",
        }
    out: list[dict[str, Any]] = []
    for ns in nameservers:
        out.append(await asyncio.to_thread(_try_axfr_sync, d, ns))
    return {
        "domain": d,
        "nameservers": nameservers,
        "results": out,
        "any_leak": any(r.get("leaked") for r in out),
    }
