"""TLS deep audit — protocol versions, cipher, SAN match, chain trust.

This complements ``tls_info.fetch_peer_info`` (which only fetches the
end-entity cert). Here we:

* Try negotiating TLS 1.3, 1.2, 1.1 (deprecated), and 1.0 (deprecated)
  against the host with stdlib ``ssl`` to see what the server actually
  supports.
* Verify the chain against the system trust store.
* Pull the peer certificate for SAN matching against the requested host.
* Record the chosen cipher suite.

We use synchronous ``ssl`` per protocol (cheap, ~0.5–1.5s each) and run
the whole thing in ``asyncio.to_thread`` so the worker stays async.

This is not a complete testssl.sh replacement — that would need raw
OpenSSL parsing — but it surfaces every common TLS misconfiguration in a
result_json shape that the UI can render directly.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)


_PROTOCOLS_TO_TRY: tuple[tuple[str, int], ...] = (
    ("TLSv1_3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1_2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1_1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1", ssl.TLSVersion.TLSv1),
)


def _parse_asn1_time(d: str) -> datetime | None:
    try:
        return datetime.strptime(d, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _hostname_matches_san(host: str, san_dns: list[str]) -> bool:
    h = host.lower().strip(".")
    for entry in san_dns:
        e = entry.lower().strip(".")
        if e == h:
            return True
        if e.startswith("*."):
            suffix = e[1:]
            if h.endswith(suffix) and "." not in h[: -len(suffix)]:
                return True
    return False


def _attempt_one(host: str, port: int, label: str, version: ssl.TLSVersion, timeout: float) -> dict[str, Any]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we want the cipher even on weak chains
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return {
                    "version_label": label,
                    "supported": True,
                    "negotiated_version": ssock.version(),
                    "cipher_name": cipher[0] if cipher else None,
                    "cipher_protocol": cipher[1] if cipher else None,
                    "cipher_secret_bits": cipher[2] if cipher else None,
                }
    except (ssl.SSLError, ConnectionResetError, OSError) as exc:
        return {
            "version_label": label,
            "supported": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _verified_chain(host: str, port: int, timeout: float) -> dict[str, Any]:
    out: dict[str, Any] = {"trusted": False, "subject": None, "san": [], "issuer": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert: dict | None = ssock.getpeercert()
                out["trusted"] = True
                if cert:
                    subj: dict[str, str] = {}
                    for part in cert.get("subject", ()):
                        for k, v in part:
                            subj[k] = v
                    issuer: dict[str, str] = {}
                    for part in cert.get("issuer", ()):
                        for k, v in part:
                            issuer[k] = v
                    san = [v for t, v in cert.get("subjectAltName", ()) if t in ("DNS", "IP Address")]
                    nb = _parse_asn1_time(cert.get("notBefore", "")) if isinstance(cert.get("notBefore"), str) else None
                    na = _parse_asn1_time(cert.get("notAfter", "")) if isinstance(cert.get("notAfter"), str) else None
                    days_left: int | None = None
                    if na is not None:
                        days_left = max(0, (na - datetime.now(tz=timezone.utc)).days)
                    out.update(
                        {
                            "subject": subj,
                            "issuer": issuer,
                            "san": san,
                            "san_matches_host": _hostname_matches_san(host, san),
                            "not_before": nb.isoformat() if nb else None,
                            "not_after": na.isoformat() if na else None,
                            "days_left": days_left,
                        }
                    )
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"cert verify failed: {exc}"
    except ssl.SSLError as exc:
        out["error"] = f"ssl error: {exc}"
    except (ConnectionRefusedError, OSError) as exc:
        out["error"] = f"socket error: {exc}"
    return out


def _audit_sync(host: str, port: int, timeout: float) -> dict[str, Any]:
    if not host:
        return {"ok": False, "error": "empty host"}
    protocols: list[dict[str, Any]] = []
    for label, version in _PROTOCOLS_TO_TRY:
        protocols.append(_attempt_one(host, port, label, version, timeout))
    chain = _verified_chain(host, port, timeout)
    weak = [p["version_label"] for p in protocols if p.get("supported") and p["version_label"] in ("TLSv1", "TLSv1_1")]
    modern = [p["version_label"] for p in protocols if p.get("supported") and p["version_label"] in ("TLSv1_2", "TLSv1_3")]

    grade = "A"
    issues: list[str] = []
    if weak:
        grade = "C"
        issues.append(f"Deprecated protocol(s) supported: {', '.join(weak)}")
    if not chain.get("trusted"):
        grade = "F"
        if chain.get("error"):
            issues.append(f"Chain not trusted: {chain['error']}")
    if not modern:
        grade = "F"
        issues.append("No modern TLS (1.2/1.3) negotiated")
    if chain.get("trusted") and chain.get("san_matches_host") is False:
        grade = "B" if grade == "A" else grade
        issues.append("SAN does not include the requested hostname")

    return {
        "ok": True,
        "host": host,
        "port": port,
        "protocols": protocols,
        "modern_supported": modern,
        "deprecated_supported": weak,
        "chain": chain,
        "grade": grade,
        "issues": issues,
    }


async def deep_audit(host: str, port: int = 443, *, timeout: float = 8.0) -> dict[str, Any]:
    return await asyncio.to_thread(_audit_sync, host, int(port or 443), float(timeout))
