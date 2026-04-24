"""Inference tests using a mock model so we don't depend on the artifact."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.modules.ids.services import flow, inference


class FakeModel:
    classes_ = ["normal", "neptune"]
    feature_names_in_ = inference.NSL_KDD_FEATURES

    def predict(self, X):  # noqa: N803
        # First feature > 0.5 means "attack"; otherwise normal.
        return ["neptune" if row[0] > 0.5 else "normal" for row in X]

    def predict_proba(self, X):  # noqa: N803
        out = []
        for row in X:
            if row[0] > 0.5:
                out.append([0.1, 0.9])
            else:
                out.append([0.95, 0.05])
        return out


@pytest.fixture(autouse=True)
def _patch_loader():
    inference._load_model.cache_clear()
    bundle = {
        "model": FakeModel(),
        "feature_list": inference.NSL_KDD_FEATURES,
        "classes": ["normal", "neptune"],
        "trained_at": None,
        "accuracy": 0.99,
        "notes": "test fixture",
    }
    with patch.object(inference, "_load_model", return_value=bundle), patch.object(
        inference, "is_available", return_value=True
    ):
        yield
    inference._load_model.cache_clear()


def test_predict_benign() -> None:
    res = inference.predict({"duration": 0.1, "src_bytes": 100})
    assert res["label"] == "benign"
    assert res["prediction"] == "normal"
    assert 0.0 <= res["probability"] <= 1.0


def test_predict_attack() -> None:
    res = inference.predict({"duration": 0.9, "src_bytes": 100})
    assert res["label"] == "attack"
    assert res["prediction"] == "neptune"
    assert res["attack_class"] == "dos"


def test_predict_bulk_count() -> None:
    rows = [{"duration": v} for v in (0.1, 0.9, 0.2)]
    out = inference.predict_bulk(rows)
    assert len(out) == 3


def test_http_log_aliases_normalise_to_flow_features() -> None:
    out = flow.normalise(
        {
            "url": "https://example.com/login",
            "method": "POST",
            "status_code": 200,
            "request_bytes": 100,
            "response_bytes": 2048,
        }
    )
    assert out["protocol_type"] == "tcp"
    assert out["service"] == "http"
    assert out["flag"] == "SF"
    assert out["src_bytes"] == 100
    assert out["dst_bytes"] == 2048
