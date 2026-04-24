"""Flow feature shaping helpers.

The IDS model consumes NSL-KDD style network-flow features. Real deployments
usually obtain these from Zeek, NetFlow/IPFIX, Suricata eve.json, or a PCAP
feature extractor. This module accepts that canonical schema plus common aliases
from HTTP access/proxy logs so the API is useful with real operational records.
"""
from __future__ import annotations

from typing import Any

ALIASES: dict[str, str] = {
    "proto": "protocol_type",
    "protocol": "protocol_type",
    "network_protocol": "protocol_type",
    "svc": "service",
    "app": "service",
    "application": "service",
    "src": "src_bytes",
    "dst": "dst_bytes",
    "src_byte": "src_bytes",
    "dst_byte": "dst_bytes",
    "bytes_in": "src_bytes",
    "request_bytes": "src_bytes",
    "bytes_out": "dst_bytes",
    "response_bytes": "dst_bytes",
    "bytes": "dst_bytes",
    "status_code": "http_status",
}


def normalise(features: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in features.items():
        out[ALIASES.get(k, k)] = v
    _derive_http_defaults(out)
    return out


def normalise_many(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalise(r) for r in rows]


def _derive_http_defaults(out: dict[str, Any]) -> None:
    if "url" in out or "method" in out or "http_status" in out:
        out.setdefault("protocol_type", "tcp")
        out.setdefault("service", "http")
    if "protocol_type" in out and isinstance(out["protocol_type"], str):
        out["protocol_type"] = out["protocol_type"].lower()
    if "service" in out and isinstance(out["service"], str):
        out["service"] = out["service"].lower()
    if "http_status" in out and "flag" not in out:
        try:
            status = int(out["http_status"])
        except (TypeError, ValueError):
            status = 0
        out["flag"] = "SF" if 200 <= status < 500 else "REJ"
    out.setdefault("flag", "SF")
