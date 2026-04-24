"""Best-effort STIX 2.1 indicator extraction for IOC storage."""
from __future__ import annotations

import re
import uuid
from typing import Any

_CIDR = re.compile(
    r"\[ipv4-addr:value\s*=\s*'([^']+)'\]|\[ipv4-addr:value\s*=\s*\"([^\"]+)\"\]"
)
_DOMAIN = re.compile(
    r"\[domain-name:value\s*=\s*'([^']+)'\]|\[domain-name:value\s*=\s*\"([^\"]+)\"\]"
)
_URL = re.compile(
    r"\[url:value\s*=\s*'([^']+)'\]|\[url:value\s*=\s*\"([^\"]+)\"\]"
)
_HASH = re.compile(
    r"\[file:hashes\.'(SHA-256|MD5)'\s*=\s*'([a-fA-F0-9]+)'\]")


def _add(rows: list[dict[str, Any]], ioc_type: str, value: str, stix_id: str | None) -> None:
    value = value.strip()
    if not value:
        return
    rows.append(
        {
            "ioc_type": ioc_type,
            "value": value.lower() if "://" not in value else value,
            "stix_id": stix_id,
            "metadata": {"stix": True, "stix_id": stix_id},
        }
    )


def extract_from_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    objects = bundle.get("objects")
    if objects is None and bundle.get("type") == "indicator":
        objects = [bundle]
    if not objects:
        return []

    rows: list[dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pat = str(obj.get("pattern", ""))
        stix_id = str(obj.get("id", "")) or None
        for m in _CIDR.finditer(pat):
            v = m.group(1) or m.group(2) or ""
            _add(rows, "ipv4", v, stix_id)
        for m in _DOMAIN.finditer(pat):
            v = m.group(1) or m.group(2) or ""
            _add(rows, "domain", v, stix_id)
        for m in _URL.finditer(pat):
            v = m.group(1) or m.group(2) or ""
            _add(rows, "url", v, stix_id)
        for m in _HASH.finditer(pat):
            htype, hv = m.group(1), m.group(2)
            _add(rows, htype.lower(), hv.lower(), stix_id)
    return rows


def synthetic_rows_from_stix2_objects(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for obj in items:
        if isinstance(obj, dict) and obj.get("type") == "indicator":
            single_object_bundle: dict[str, Any] = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [obj],
            }
            out.extend(extract_from_bundle(single_object_bundle))
    return out
