"""Bundled MITRE ATT&CK technique subset for LLM context (foundation set, not full matrix)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


@lru_cache
def load_mitre_foundation() -> list[dict[str, str]]:
    path = Path(__file__).resolve().parent / "data" / "mitre_enterprise_foundation.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        return []
    return [x for x in raw if isinstance(x, dict) and "id" in x]


def mitre_addendum_for_prompt(max_lines: int = 40) -> str:
    rows = load_mitre_foundation()[:max_lines]
    lines = [f"- {r['id']}: {r.get('name', '')} ({r.get('tactic', '')})" for r in rows]
    return "\n".join(lines)
