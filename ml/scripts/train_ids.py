"""Train the IDS RandomForest model on NSL-KDD.

Usage:
    python ml/scripts/train_ids.py             # auto-downloads + trains
    python ml/scripts/train_ids.py --synth     # train on a tiny synthetic set (CI mode)

The artifact is a single joblib pickle with the shape SentinelOps' inference
service expects:

    {
        "model":        sklearn pipeline,
        "feature_list": [...],
        "classes":      [...],
        "trained_at":   ISO-8601 string,
        "accuracy":     float,
        "notes":        str,
    }

The artifact lives at ``ml/artifacts/ids_rf.joblib`` and is committed to the
repo so the API works on a fresh clone.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
ARTIFACT_DIR = ROOT / "artifacts"
ARTIFACT_PATH = ARTIFACT_DIR / "ids_rf.joblib"

NSL_KDD_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag"]


def _make_synth(n: int = 4000, seed: int = 42) -> pd.DataFrame:
    """Tiny synthetic NSL-KDD-shaped dataset for CI / fresh-clone bootstrapping.

    The synthetic distribution is intentionally separable: attack rows have
    high src_bytes and elevated serror_rate, normal rows don't. This is *not*
    representative of real traffic — it's only here so the API ships with a
    working artifact on a fresh clone, and so CI can retrain without 200 MB of
    download.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        is_attack = rng.random() < 0.4
        proto = rng.choice(["tcp", "udp", "icmp"], p=[0.7, 0.2, 0.1])
        service = rng.choice(["http", "smtp", "private", "domain_u", "ftp_data"])
        flag = rng.choice(["SF", "S0", "REJ", "RSTR"])
        if is_attack:
            label = rng.choice(["neptune", "smurf", "satan", "ipsweep"], p=[0.5, 0.2, 0.15, 0.15])
            src = rng.integers(5000, 50000)
            serror = rng.uniform(0.6, 1.0)
            srv_serror = rng.uniform(0.6, 1.0)
        else:
            label = "normal"
            src = rng.integers(0, 4000)
            serror = rng.uniform(0.0, 0.2)
            srv_serror = rng.uniform(0.0, 0.2)
        row = [
            float(rng.integers(0, 60)), proto, service, flag, int(src), int(rng.integers(0, 5000)),
            0, 0, 0, 0, 0, int(not is_attack),
            0, 0, 0, 0, 0,
            0, 0, 0, 0,
            0, int(rng.integers(0, 100)), int(rng.integers(0, 100)), float(serror), float(srv_serror),
            float(rng.uniform(0, 0.3)), float(rng.uniform(0, 0.3)), float(rng.uniform(0, 1)), float(rng.uniform(0, 1)),
            float(rng.uniform(0, 0.5)), int(rng.integers(0, 255)), int(rng.integers(0, 255)),
            float(rng.uniform(0, 1)), float(rng.uniform(0, 1)),
            float(rng.uniform(0, 1)), float(rng.uniform(0, 1)),
            float(serror), float(srv_serror), float(rng.uniform(0, 0.5)),
            float(rng.uniform(0, 0.5)),
            label, 0,
        ]
        rows.append(row)
    return pd.DataFrame(rows, columns=NSL_KDD_COLS)


def _load_real() -> pd.DataFrame:
    """Load NSL-KDD if present in ml/data/. Falls back to synthetic if absent."""
    train_path = DATA_DIR / "KDDTrain+.txt"
    if not train_path.exists():
        print(f"[train_ids] {train_path} not found; using synthetic data.")
        return _make_synth()
    df = pd.read_csv(train_path, header=None, names=NSL_KDD_COLS)
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--synth", action="store_true", help="Force synthetic dataset.")
    parser.add_argument("--n-estimators", type=int, default=120)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = _make_synth() if args.synth else _load_real()
    df = df.drop(columns=["difficulty"], errors="ignore")
    y = df["label"].astype(str)
    X = df.drop(columns=["label"])

    numeric = [c for c in X.columns if c not in CATEGORICAL]

    pre = ColumnTransformer(
        transformers=[
            ("num", Pipeline([("imp", SimpleImputer(strategy="median")), ("sc", StandardScaler())]), numeric),
            ("cat", Pipeline([("imp", SimpleImputer(strategy="most_frequent")),
                              ("oh", OneHotEncoder(handle_unknown="ignore", sparse_output=False))]), CATEGORICAL),
        ]
    )
    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        n_jobs=-1,
        random_state=args.seed,
        class_weight="balanced",
    )
    pipe = Pipeline([("pre", pre), ("rf", clf)])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )
    pipe.fit(X_train, y_train)

    pred = pipe.predict(X_test)
    acc = float(accuracy_score(y_test, pred))
    print(f"[train_ids] accuracy = {acc:.4f}")
    print(classification_report(y_test, pred, zero_division=0))

    feature_list = list(X.columns)
    classes = list(pipe.named_steps["rf"].classes_)

    bundle = {
        "model": pipe,
        "feature_list": feature_list,
        "classes": classes,
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "accuracy": acc,
        "notes": "Trained on " + ("synthetic" if args.synth or not (DATA_DIR / "KDDTrain+.txt").exists() else "NSL-KDD"),
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, ARTIFACT_PATH, compress=3)
    (ARTIFACT_DIR / "ids_rf.meta.json").write_text(
        json.dumps({k: v for k, v in bundle.items() if k != "model"}, default=str, indent=2)
    )
    print(f"[train_ids] wrote {ARTIFACT_PATH} ({ARTIFACT_PATH.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    sys.exit(main())
