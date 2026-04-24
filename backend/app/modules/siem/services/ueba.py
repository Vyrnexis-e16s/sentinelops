"""Per-source volume baselines (UEBA-style deviation scoring, lightweight)."""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.siem.models import Event


@dataclass(slots=True)
class SourceSummary:
    source: str
    count_24h: int
    count_30d: int
    daily_baseline: float
    z_score: float
    deviates: bool

    def model_dump(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "count_24h": self.count_24h,
            "count_30d": self.count_30d,
            "daily_baseline": round(self.daily_baseline, 3),
            "z_score": round(self.z_score, 3),
            "deviates": self.deviates,
        }


async def build_source_ueba(db: AsyncSession) -> list[SourceSummary]:
    now = datetime.now(tz=timezone.utc)
    d1 = now - timedelta(days=1)
    d30 = now - timedelta(days=30)

    # last 30d counts
    r30 = await db.execute(
        select(Event.source, func.count())
        .where(Event.timestamp >= d30)
        .group_by(Event.source)
    )
    c30 = {row[0]: int(row[1]) for row in r30.all()}

    r24 = await db.execute(
        select(Event.source, func.count())
        .where(Event.timestamp >= d1)
        .group_by(Event.source)
    )
    c24 = {row[0]: int(row[1]) for row in r24.all()}

    sources = set(c30) | set(c24)
    out: list[SourceSummary] = []
    for s in sorted(sources):
        n30 = c30.get(s, 0)
        n24 = c24.get(s, 0)
        baseline = n30 / 30.0 if n30 else 0.0
        # treat daily rate ~ Poisson: sd ~ sqrt(baseline) per day, compare 24h count to baseline
        expected_24h = baseline
        if expected_24h <= 0 and n24 == 0:
            z = 0.0
        elif expected_24h <= 0:
            z = 5.0
        else:
            # Normal approx on Poisson: var = expected (per day) -> for 1 day, sd = sqrt(baseline)
            sd = math.sqrt(max(baseline, 1e-9))
            z = (n24 - expected_24h) / sd if sd > 0 else 0.0
        out.append(
            SourceSummary(
                source=s,
                count_24h=n24,
                count_30d=n30,
                daily_baseline=baseline,
                z_score=float(z),
                deviates=abs(float(z)) >= 2.0,
            )
        )
    return out
