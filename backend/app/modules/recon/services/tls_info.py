"""TLS peer certificate details (lab use — not a full PKI audit)."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

def _parse_asn1_time(d: str) -> datetime | None:
    try:
        return datetime.strptime(d, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _peer_cert_sync(host: str, port: int) -> dict[str, Any]:
    h = (host or "").strip()
    p = int(port) if 1 <= int(port) <= 65535 else 443
    if not h:
        return {"ok": False, "error": "empty host"}

    ctx = ssl.create_default_context()
    with socket.create_connection((h, p), timeout=12) as raw:
        with ctx.wrap_socket(raw, server_hostname=h) as ssock:
            cert: dict | None = ssock.getpeercert()  # type: ignore[assignment]
            if not cert:
                return {"ok": False, "error": "no certificate"}
            subj: dict[str, str] = {}
            for part in cert.get("subject", ()):
                for k, v in part:
                    subj[k] = v
            san = [v for t, v in cert.get("subjectAltName", ()) if t in ("DNS", "IP Address")]
            not_before, not_after = cert.get("notBefore"), cert.get("notAfter")
            nb = _parse_asn1_time(not_before) if isinstance(not_before, str) else None
            na = _parse_asn1_time(not_after) if isinstance(not_after, str) else None
            now = datetime.now(tz=timezone.utc)
            days_left: int | None = None
            if na is not None:
                days_left = max(0, (na - now).days)
            return {
                "ok": True,
                "tls_version": ssock.version(),
                "subject": subj,
                "san": san,
                "not_before": nb.isoformat() if nb else None,
                "not_after": na.isoformat() if na else None,
                "days_left": days_left,
            }


async def fetch_peer_info(host: str, port: int = 443) -> dict[str, Any]:
    return await asyncio.to_thread(_peer_cert_sync, host, port)
