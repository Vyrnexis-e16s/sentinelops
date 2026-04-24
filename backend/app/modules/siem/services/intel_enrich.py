"""IOC extraction from event documents and match against ``ThreatIoc`` rows."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

# Rough IPv4 pattern for candidate extraction from arbitrary strings
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b"
)


def _walk(obj: Any, out: set[str]) -> None:
    if obj is None:
        return
    if isinstance(obj, str):
        s = obj.strip()
        if s:
            out.add(s.lower())
        for m in _IPV4.finditer(obj):
            out.add(m.group(0).lower())
        return
    if isinstance(obj, Mapping):
        for v in obj.values():
            _walk(v, out)
        return
    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        for v in obj:
            _walk(v, out)


def collect_candidate_tokens(event_doc: dict[str, Any]) -> set[str]:
    """Flatten strings/IPs from ``raw`` + ``parsed`` (and top-level) into lowercase keys."""
    out: set[str] = set()
    _walk(event_doc, out)
    return out


def find_ioc_hits(
    candidates: set[str], known: set[tuple[str, str]]
) -> list[tuple[str, str]]:
    """Return list of (ioc_type, value) for values that appear in ``candidates`` (exact)."""
    hits: list[tuple[str, str]] = []
    for t, v in known:
        if v in candidates:
            hits.append((t, v))
    return hits
