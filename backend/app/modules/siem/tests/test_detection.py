"""Unit tests for the SIEM rule engine and anomaly scorer."""
from __future__ import annotations

from app.modules.siem.services.detection import (
    evaluate_condition,
    evaluate_rule,
    iqr_anomaly_score,
)


EVENT = {
    "source": "sshd",
    "parsed": {"event_type": "auth_failure", "failed_count": 12, "user": "root"},
    "raw": {"msg": "Failed password for root from 10.0.0.1"},
}


def test_condition_eq() -> None:
    assert evaluate_condition(EVENT, {"field": "source", "op": "eq", "value": "sshd"})
    assert not evaluate_condition(EVENT, {"field": "source", "op": "eq", "value": "dns"})


def test_condition_gte() -> None:
    assert evaluate_condition(
        EVENT, {"field": "parsed.failed_count", "op": "gte", "value": 5}
    )
    assert not evaluate_condition(
        EVENT, {"field": "parsed.failed_count", "op": "gte", "value": 100}
    )


def test_condition_contains() -> None:
    assert evaluate_condition(
        EVENT, {"field": "raw.msg", "op": "contains", "value": "Failed password"}
    )


def test_condition_regex() -> None:
    assert evaluate_condition(
        EVENT,
        {"field": "raw.msg", "op": "regex", "value": r"from \d+\.\d+\.\d+\.\d+"},
    )


def test_condition_in() -> None:
    assert evaluate_condition(
        EVENT, {"field": "parsed.user", "op": "in", "value": ["root", "admin"]}
    )


def test_rule_all_of_match() -> None:
    rule = {
        "name": "brute_force",
        "query_dsl": {
            "all_of": [
                {"field": "source", "op": "eq", "value": "sshd"},
                {"field": "parsed.failed_count", "op": "gte", "value": 5},
            ],
            "score": 7.5,
            "severity": "high",
        },
        "attack_technique_ids": ["T1110"],
    }
    match = evaluate_rule(EVENT, rule)
    assert match.matched
    assert match.score == 7.5
    assert match.severity == "high"
    assert match.technique_ids == ["T1110"]


def test_rule_none_of_blocks() -> None:
    rule = {
        "name": "filtered",
        "query_dsl": {
            "all_of": [{"field": "source", "op": "eq", "value": "sshd"}],
            "none_of": [{"field": "parsed.user", "op": "eq", "value": "root"}],
            "score": 1.0,
        },
    }
    assert not evaluate_rule(EVENT, rule).matched


def test_rule_any_of_matches_one() -> None:
    rule = {
        "name": "ps",
        "query_dsl": {
            "all_of": [{"field": "source", "op": "eq", "value": "sshd"}],
            "any_of": [
                {"field": "parsed.user", "op": "eq", "value": "nonexistent"},
                {"field": "parsed.user", "op": "eq", "value": "root"},
            ],
        },
    }
    assert evaluate_rule(EVENT, rule).matched


def test_iqr_outlier_detected() -> None:
    history = {"bytes_out": [100, 110, 105, 98, 102, 108, 111, 99]}
    normal = iqr_anomaly_score({"bytes_out": 104}, history)
    anomalous = iqr_anomaly_score({"bytes_out": 5000}, history)
    assert normal.score == 0.0
    assert anomalous.score > 0.5
    assert "bytes_out" in anomalous.outlier_fields


def test_iqr_insufficient_history() -> None:
    history = {"x": [1.0, 2.0]}
    result = iqr_anomaly_score({"x": 999.0}, history)
    assert result.score == 0.0
