"""Sigma YAML → native :class:`RuleDSL` (limited subset; see /siem/sigma/compile)."""
from __future__ import annotations

import re
from typing import Any

import yaml

from app.modules.siem.schemas import RuleCondition, RuleDSL, Severity

# Bound Sigma condition strings to avoid ReDoS / pathological input (CodeQL: polynomial regex on uncontrolled data).
_MAX_CONDITION_LEN = 4096
_MAX_KEY_LEN = 512


def _field_name(sigma_name: str, default_prefix: str) -> str:
    n = sigma_name.strip()
    if n.startswith("parsed.") or n.startswith("raw."):
        return n
    return f"{default_prefix}.{n}"


def _parse_sigma_key(k: str) -> tuple[str, str] | None:
    """Parse ``field|modifier`` without applying regex to full user-controlled keys."""
    k0 = k.strip()
    if not k0 or len(k0) > _MAX_KEY_LEN:
        return None
    if "|" in k0:
        base, mod = k0.rsplit("|", 1)
        base, mod = base.strip(), mod.strip().lower()
        if not mod:
            mod = ""
        elif not all(c.isascii() and (c.isalnum() or c == "_") for c in mod):
            return None
    else:
        base, mod = k0, ""
    if not base:
        return None
    return base, mod


def _map_selection_block(
    block: Any, default_prefix: str
) -> list[RuleCondition]:
    if not isinstance(block, dict):
        raise ValueError("selection must be a mapping of field|modifier: value")
    out: list[RuleCondition] = []
    for k, v in block.items():
        pk = _parse_sigma_key(k)
        if not pk:
            continue
        base, mod = pk
        field = _field_name(base, default_prefix)
        if mod in ("", "eq", "equals"):
            out.append(RuleCondition(field=field, op="eq", value=v))
        elif mod in ("contains",):
            out.append(RuleCondition(field=field, op="contains", value=str(v)))
        elif mod in ("startswith", "prefix"):
            out.append(
                RuleCondition(field=field, op="regex", value=f"^{re.escape(str(v))}")
            )
        elif mod in ("endswith", "suffix"):
            out.append(
                RuleCondition(field=field, op="regex", value=f"{re.escape(str(v))}$")
            )
        else:
            raise ValueError(
                f"Unsupported modifier {mod!r} on {k!r} — use eq, contains, startswith, endswith"
            )
    return out


def _split_condition_by_and(expr: str) -> list[str]:
    """Split on `` and `` (case-insensitive) without regex over arbitrary-length input."""
    e = expr
    n = len(e)
    if n == 0:
        return []
    le = e.lower()
    sep = " and "
    L = len(sep)
    parts: list[str] = []
    start = 0
    i = 0
    while i <= n - L:
        if le[i : i + L] == sep:
            parts.append(e[start:i].strip())
            start = i + L
            i = start
            continue
        i += 1
    parts.append(e[start:].strip())
    return [p for p in parts if p]


def _parse_condition(expr: str, blocks: dict[str, list[RuleCondition]]) -> RuleDSL:
    raw = str(expr)
    if len(raw) > _MAX_CONDITION_LEN:
        raise ValueError("detection.condition exceeds maximum length")
    e = " ".join(raw.split())
    e_low = e.lower()

    if e_low.startswith("1 of "):
        rest = e[5:].strip()
        names: list[str] = []
        for part in rest.split(",") if rest else []:
            x = part.strip()
            if not x or x.lower().startswith("filter"):
                continue
            x = x.replace("*", "")
            names.append(x)
        if not names:
            raise ValueError("empty 1 of")
        any_of: list[RuleCondition] = []
        for n in names:
            n = n.rstrip("*")
            matches = [k for k in blocks if k.startswith(n.rstrip("*"))]
            for blk_name in (matches or ([n] if n in blocks else [])):
                any_of.extend(blocks.get(blk_name, []))
        if not any_of:
            raise ValueError("1 of could not resolve any selection blocks")
        return RuleDSL(any_of=any_of, score=6.0, severity="high")

    if e in blocks and blocks[e]:
        return RuleDSL(all_of=blocks[e], score=5.0, severity="medium")

    if " and " in e.lower():
        parts = _split_condition_by_and(e)
        merged: list[RuleCondition] = []
        for p in parts:
            p = p.strip()
            if p not in blocks:
                raise ValueError(f"unknown selection block {p!r}")
            merged.extend(blocks[p])
        return RuleDSL(all_of=merged, score=6.0, severity="high")

    raise ValueError(
        f"Unsupported condition {e!r} — use a single block name, block1 and block2, or 1 of sel_*"
    )


def compile_sigma_yaml(raw: str, *, field_prefix: str = "parsed") -> tuple[str, str, RuleDSL]:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("Sigma document must be a YAML object")

    title = str(data.get("title") or data.get("id") or "imported-sigma")
    desc = str(data.get("description") or "")
    det = data.get("detection")
    if not isinstance(det, dict):
        raise ValueError("Sigma 'detection' must be a mapping")

    blocks: dict[str, list[RuleCondition]] = {}
    for k, v in det.items():
        if k in {"condition", "timeframe"} or k.startswith("filter"):
            continue
        if isinstance(v, dict):
            blocks[k] = _map_selection_block(v, field_prefix)

    cond = det.get("condition")
    if not cond:
        if len(blocks) == 1:
            cond = next(iter(blocks.keys()))
        else:
            raise ValueError("Set detection.condition or use a single selection block")
    assert cond is not None
    dsl = _parse_condition(str(cond), blocks)

    lev = str(data.get("level", "")).lower()
    if lev:
        sev: Severity
        if lev in ("informational", "info"):
            sev, sc = "info", 2.0
        elif lev == "low":
            sev, sc = "low", 3.0
        elif lev == "medium":
            sev, sc = "medium", 5.0
        elif lev == "high":
            sev, sc = "high", 7.0
        elif lev == "critical":
            sev, sc = "critical", 9.0
        else:
            sev, sc = "medium", float(dsl.score)
        dsl = RuleDSL(
            all_of=dsl.all_of,
            any_of=dsl.any_of,
            none_of=dsl.none_of,
            severity=sev,
            score=max(float(dsl.score), sc),
        )
    return title, desc, dsl


__all__ = ["compile_sigma_yaml"]
