"""Quick smoke test: load the artifact and run one prediction.

    python ml/scripts/test_inference.py
"""
from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from train_ids import NSL_KDD_COLS

ARTIFACT = Path(__file__).resolve().parents[1] / "artifacts" / "ids_rf.joblib"


def main() -> None:
    if not ARTIFACT.exists():
        raise SystemExit(f"missing artifact: {ARTIFACT}; run train_ids.py first")
    bundle = joblib.load(ARTIFACT)
    model = bundle["model"]

    feature_cols = [c for c in NSL_KDD_COLS if c not in ("label", "difficulty")]
    sample = pd.DataFrame(
        [[0] * len(feature_cols)],
        columns=feature_cols,
    )
    sample["protocol_type"] = "tcp"
    sample["service"] = "http"
    sample["flag"] = "SF"
    sample["src_bytes"] = 30000
    sample["serror_rate"] = 0.9

    pred = model.predict(sample)[0]
    proba = model.predict_proba(sample)[0]
    print(f"prediction = {pred}")
    print(f"max prob   = {max(proba):.3f}")
    print(f"classes    = {list(model.classes_)}")


if __name__ == "__main__":
    main()
