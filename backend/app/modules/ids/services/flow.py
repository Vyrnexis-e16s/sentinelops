"""Lightweight flow feature shaping helpers.

A real deployment would parse pcap or NetFlow records into the canonical NSL-KDD
feature schema. We provide a tiny stub that takes whatever the caller hands us
and normalises a couple of common alias names.
"""
from __future__ import annotations

from typing import Any

ALIASES: dict[str, str] = {
    "proto": "protocol_type",
    "protocol": "protocol_type",
    "svc": "service",
    "src": "src_bytes",
    "dst": "dst_bytes",
    "src_byte": "src_bytes",
    "dst_byte": "dst_bytes",
}


def normalise(features: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in features.items():
        out[ALIASES.get(k, k)] = v
    return out


def normalise_many(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalise(r) for r in rows]
