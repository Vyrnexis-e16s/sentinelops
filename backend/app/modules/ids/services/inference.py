"""IDS inference service.

Loads a scikit-learn pipeline (joblib) at first use and caches it. The pipeline
must expose ``predict`` and ``predict_proba`` and carry the feature list as
``feature_names_in_`` (sklearn standard) or as a ``feature_list`` attribute.

Designed to gracefully degrade: if the artifact is missing the service will
return HTTP 503 from the router rather than crashing the worker.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)


# NSL-KDD canonical feature list (41 cols). Used when the artifact carries no
# feature_names_in_ attribute (e.g. some pickled raw classifiers).
NSL_KDD_FEATURES: list[str] = [
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
    "dst_host_srv_rerror_rate",
]

# Coarse attack-class mapping (NSL-KDD groups).
ATTACK_CLASS_MAP: dict[str, str] = {
    "normal": "benign",
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos", "udpstorm": "dos",
    "processtable": "dos", "worm": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "httptunnel": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}


class ModelUnavailable(Exception):
    """Raised when the IDS artifact is missing or invalid."""


@lru_cache(maxsize=1)
def _load_model() -> dict[str, Any]:
    """Load the joblib model once. Expensive; cache at process scope."""
    import joblib  # imported lazily so tests can stub _load_model directly

    path = settings.ids_model_path
    if not os.path.exists(path):
        raise ModelUnavailable(f"IDS model artifact not found at {path}")

    payload = joblib.load(path)

    # Two acceptable artifact shapes:
    #   1. A dict with {"model": ..., "feature_list": [...], "trained_at": ..., "accuracy": ...}
    #   2. A bare estimator (we infer feature names from sklearn attribute or fallback to NSL-KDD)
    if isinstance(payload, dict) and "model" in payload:
        meta = payload
    else:
        meta = {"model": payload}

    model = meta["model"]
    feature_list = (
        meta.get("feature_list")
        or list(getattr(model, "feature_names_in_", []))
        or NSL_KDD_FEATURES
    )
    classes = list(getattr(model, "classes_", meta.get("classes", [])))

    log.info(
        "ids_model_loaded",
        path=path,
        n_features=len(feature_list),
        n_classes=len(classes),
        accuracy=meta.get("accuracy"),
    )

    return {
        "model": model,
        "feature_list": feature_list,
        "classes": classes,
        "trained_at": meta.get("trained_at"),
        "accuracy": meta.get("accuracy"),
        "notes": meta.get("notes"),
    }


def _vectorise(features: dict[str, Any], feature_list: list[str]) -> list[float]:
    """Map an arbitrary feature dict onto the trained feature order.

    Missing values become 0.0 (the model's training pipeline should already
    impute medians upstream — this is a last-line default).
    """
    row: list[float] = []
    for name in feature_list:
        v = features.get(name, 0.0)
        if isinstance(v, str):
            # categorical-as-string → cheap stable hash, scaled tiny
            v = (hash(v) & 0xFFFF) / 65535.0
        try:
            row.append(float(v))
        except (TypeError, ValueError):
            row.append(0.0)
    return row


def is_available() -> bool:
    return Path(settings.ids_model_path).exists()


def model_info() -> dict[str, Any]:
    """Return metadata; never raises."""
    if not is_available():
        return {
            "trained_at": None,
            "accuracy": None,
            "feature_count": len(NSL_KDD_FEATURES),
            "feature_list": NSL_KDD_FEATURES,
            "classes": [],
            "artifact_present": False,
            "artifact_path": settings.ids_model_path,
            "notes": "Run `python ml/scripts/train_ids.py` to produce an artifact.",
        }
    try:
        bundle = _load_model()
    except ModelUnavailable as exc:
        return {
            "trained_at": None,
            "accuracy": None,
            "feature_count": len(NSL_KDD_FEATURES),
            "feature_list": NSL_KDD_FEATURES,
            "classes": [],
            "artifact_present": False,
            "artifact_path": settings.ids_model_path,
            "notes": str(exc),
        }
    return {
        "trained_at": bundle.get("trained_at"),
        "accuracy": bundle.get("accuracy"),
        "feature_count": len(bundle["feature_list"]),
        "feature_list": bundle["feature_list"],
        "classes": [str(c) for c in bundle["classes"]],
        "artifact_present": True,
        "artifact_path": settings.ids_model_path,
        "notes": bundle.get("notes"),
    }


def predict(features: dict[str, Any]) -> dict[str, Any]:
    """Run inference for one flow and return a result dict."""
    bundle = _load_model()
    model = bundle["model"]
    feature_list = bundle["feature_list"]

    row = _vectorise(features, feature_list)
    pred = model.predict([row])[0]
    proba = float(max(model.predict_proba([row])[0])) if hasattr(model, "predict_proba") else 1.0

    pred_str = str(pred)
    label = "benign" if pred_str in ("normal", "benign", "0") else "attack"
    attack_class = ATTACK_CLASS_MAP.get(pred_str, None if label == "benign" else "other")

    return {
        "timestamp": datetime.now(tz=timezone.utc),
        "features": features,
        "prediction": pred_str,
        "probability": proba,
        "label": label,
        "attack_class": attack_class,
    }


def predict_bulk(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [predict(r) for r in rows]
