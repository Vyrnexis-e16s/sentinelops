"""Reverse DNS (PTR) — best-effort using system resolver."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any


def ptr_for_ip(ip: str) -> dict[str, Any]:
    """Synchronous PTR lookup; run in a thread from async code."""
    raw = ip.strip()
    try:
        ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return {"ok": False, "error": "PTR job needs a single IPv4 or IPv6 address.", "ip": raw}
    try:
        host, alias, ips = socket.gethostbyaddr(raw)
    except socket.herror as exc:
        return {"ok": False, "error": str(exc) or "no PTR record", "ip": raw}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "ip": raw}
    return {
        "ok": True,
        "ip": raw,
        "ptr": host,
        "aliases": list(alias) if alias else [],
        "ips": list(ips) if ips else [],
    }


async def ptr_for_ip_async(ip: str) -> dict[str, Any]:
    return await asyncio.to_thread(ptr_for_ip, ip)
