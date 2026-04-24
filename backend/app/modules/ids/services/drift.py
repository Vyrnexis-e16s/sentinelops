"""Rolling feature statistics for simple drift / data-quality visibility."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ids.models import Inference


@dataclass(slots=True)
class DriftSummary:
    n_samples: int
    key: str
    mean: float
    stdev: float
    p05: float
    p95: float
    min_v: float
    max_v: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "n": self.n_samples,
            "mean": round(self.mean, 6),
            "stdev": round(self.stdev, 6) if not math.isnan(self.stdev) else None,
            "p05": round(self.p05, 6),
            "p95": round(self.p95, 6),
            "min": round(self.min_v, 6),
            "max": round(self.max_v, 6),
        }


def _percentile_sorted(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


async def feature_drift_for_key(
    db: AsyncSession, key: str, limit: int = 500
) -> DriftSummary | None:
    rows = (
        (await db.execute(select(Inference).order_by(Inference.timestamp.desc()).limit(limit)))
        .scalars()
        .all()
    )
    values: list[float] = []
    for r in rows:
        v = (r.features_json or {}).get(key)
        if v is None:
            continue
        try:
            values.append(float(v))
        except (TypeError, ValueError):
            continue
    n = len(values)
    if n < 2:
        return None
    values.sort()
    mean = sum(values) / n
    var = sum((x - mean) ** 2 for x in values) / (n - 1)
    stdev = math.sqrt(var)
    return DriftSummary(
        n_samples=n,
        key=key,
        mean=mean,
        stdev=stdev,
        p05=_percentile_sorted(values, 0.05),
        p95=_percentile_sorted(values, 0.95),
        min_v=values[0],
        max_v=values[-1],
    )
