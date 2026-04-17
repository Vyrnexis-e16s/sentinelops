"""Detection rule engine + anomaly scorer."""
from __future__ import annotations

import math
import re
import statistics
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


# --------------------------------------------------------------------------- #
# Path lookup ("a.b.c" or "a.b[0].c")                                         #
# --------------------------------------------------------------------------- #


_PATH_SEG = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _lookup(doc: Any, path: str) -> Any:
    cur = doc
    for match in _PATH_SEG.finditer(path):
        key, idx = match.group(1), match.group(2)
        if cur is None:
            return None
        if key is not None:
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        elif idx is not None:
            try:
                cur = cur[int(idx)]
            except (IndexError, TypeError, ValueError):
                return None
    return cur


# --------------------------------------------------------------------------- #
# Operators                                                                   #
# --------------------------------------------------------------------------- #


def _cmp_numeric(a: Any, b: Any, op: str) -> bool:
    try:
        af, bf = float(a), float(b)
    except (TypeError, ValueError):
        return False
    return {
        "gt": af > bf,
        "gte": af >= bf,
        "lt": af < bf,
        "lte": af <= bf,
    }[op]


def evaluate_condition(doc: dict[str, Any], cond: dict[str, Any]) -> bool:
    field = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")
    actual = _lookup(doc, field) if field else doc

    if op == "exists":
        return actual is not None
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op in {"gt", "gte", "lt", "lte"}:
        return _cmp_numeric(actual, value, op)
    if op == "contains":
        if isinstance(actual, str) and isinstance(value, str):
            return value in actual
        if isinstance(actual, list | tuple | set):
            return value in actual
        return False
    if op == "regex":
        if not isinstance(actual, str) or not isinstance(value, str):
            return False
        try:
            return re.search(value, actual) is not None
        except re.error:
            return False
    if op == "in":
        if isinstance(value, list | tuple | set):
            return actual in value
        return False
    return False


# --------------------------------------------------------------------------- #
# Rule evaluation                                                             #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class RuleMatch:
    matched: bool
    score: float
    severity: str
    rule_name: str
    technique_ids: list[str]


def evaluate_rule(event_doc: dict[str, Any], rule: dict[str, Any]) -> RuleMatch:
    """Evaluate a rule DSL blob (as stored in ``siem_rules.query_dsl_json``)."""
    dsl = rule.get("query_dsl") or rule
    all_of = dsl.get("all_of") or []
    any_of = dsl.get("any_of") or []
    none_of = dsl.get("none_of") or []

    matched = True
    if all_of and not all(evaluate_condition(event_doc, c) for c in all_of):
        matched = False
    if matched and any_of and not any(evaluate_condition(event_doc, c) for c in any_of):
        matched = False
    if matched and none_of and any(evaluate_condition(event_doc, c) for c in none_of):
        matched = False

    return RuleMatch(
        matched=matched,
        score=float(dsl.get("score", 1.0)),
        severity=str(dsl.get("severity", "medium")),
        rule_name=str(rule.get("name", "")),
        technique_ids=list(rule.get("attack_technique_ids") or []),
    )


def evaluate_many(event_doc: dict[str, Any], rules: Iterable[dict[str, Any]]) -> list[RuleMatch]:
    return [m for r in rules if r.get("enabled", True) and (m := evaluate_rule(event_doc, r)).matched]


# --------------------------------------------------------------------------- #
# Anomaly scorer — rolling IQR                                                #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class AnomalyResult:
    score: float
    outlier_fields: list[str]


def iqr_anomaly_score(
    numeric_fields: dict[str, float],
    history: dict[str, list[float]],
    k: float = 1.5,
) -> AnomalyResult:
    """Score each field by how far it lies beyond Tukey fences (k*IQR).

    Returns a score in [0, 1] where 1 == extreme outlier across all fields.
    """
    if not numeric_fields:
        return AnomalyResult(score=0.0, outlier_fields=[])

    per_field_scores: list[float] = []
    outliers: list[str] = []
    for name, value in numeric_fields.items():
        samples = history.get(name) or []
        if len(samples) < 4:
            per_field_scores.append(0.0)
            continue
        try:
            q1, _, q3 = statistics.quantiles(samples, n=4)
        except statistics.StatisticsError:
            per_field_scores.append(0.0)
            continue
        iqr = q3 - q1
        if iqr <= 0:
            per_field_scores.append(0.0)
            continue
        low = q1 - k * iqr
        high = q3 + k * iqr
        if low <= value <= high:
            per_field_scores.append(0.0)
            continue
        dist = max(low - value, value - high)
        # Squash with tanh → (0, 1)
        s = math.tanh(dist / (iqr + 1e-9))
        per_field_scores.append(s)
        if s > 0.25:
            outliers.append(name)

    return AnomalyResult(
        score=max(per_field_scores) if per_field_scores else 0.0,
        outlier_fields=outliers,
    )
