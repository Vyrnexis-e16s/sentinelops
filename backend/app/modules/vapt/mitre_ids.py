"""Validate MITRE ATT&CK technique id strings (enterprise techniques)."""
from __future__ import annotations

import re

_TECH_ID = re.compile(r"^T[0-9]{4}([.][0-9]{1,3})?$")


def is_valid_mitre_technique_id(technique_id: str) -> bool:
    tid = (technique_id or "").strip()
    return bool(_TECH_ID.match(tid))
