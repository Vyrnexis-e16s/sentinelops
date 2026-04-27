"""IDS API routes."""
from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_user
from app.models import User
from app.modules.ids import schemas
from app.modules.ids.models import Inference
from app.modules.ids.services import flow, inference
from app.modules.ids.services.drift import feature_drift_for_key
from app.services.audit import audit_logger

router = APIRouter(prefix="/ids", tags=["ids"])


def _safe_probability(p: float) -> float:
    """Avoid NaN/inf in JSON responses (Pydantic / clients can choke on non-finite floats)."""
    try:
        x = float(p)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(x):
        return 0.0
    return x


def _ensure_available() -> None:
    if not inference.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IDS model artifact not present. Run `python ml/scripts/train_ids.py`.",
        )


@router.post("/infer", response_model=schemas.InferenceResult, status_code=status.HTTP_201_CREATED)
async def infer(
    payload: schemas.InferenceRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> Any:
    _ensure_available()
    feats = flow.normalise(payload.features)
    try:
        result = inference.predict(feats, with_explain=payload.explain)
    except inference.ModelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    row = Inference(
        timestamp=result["timestamp"],
        features_json=result["features"],
        prediction=result["prediction"],
        probability=result["probability"],
        label=result["label"],
        attack_class=result["attack_class"],
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    await audit.append(
        actor_id=user.id,
        action="ids.infer",
        resource_type="ids.inference",
        resource_id=str(row.id),
        metadata={"label": row.label, "prediction": row.prediction},
    )

    return schemas.InferenceResult(
        id=row.id,
        timestamp=row.timestamp,
        prediction=row.prediction,
        probability=_safe_probability(row.probability),
        label=row.label,
        attack_class=row.attack_class,
        explanation=result.get("explanation"),
    )


@router.post("/infer/bulk", response_model=list[schemas.InferenceResult])
async def infer_bulk(
    payload: schemas.BulkInferenceRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> Any:
    _ensure_available()
    rows = flow.normalise_many(payload.flows)
    try:
        results = inference.predict_bulk(rows)
    except inference.ModelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    persisted: list[Inference] = []
    for r in results:
        row = Inference(
            timestamp=r["timestamp"],
            features_json=r["features"],
            prediction=r["prediction"],
            probability=r["probability"],
            label=r["label"],
            attack_class=r["attack_class"],
        )
        db.add(row)
        persisted.append(row)
    await db.commit()
    for row in persisted:
        await db.refresh(row)

    await audit.append(
        actor_id=user.id,
        action="ids.infer_bulk",
        resource_type="ids.inference",
        resource_id="bulk",
        metadata={"count": len(persisted)},
    )

    return [
        schemas.InferenceResult(
            id=p.id,
            timestamp=p.timestamp,
            prediction=p.prediction,
            probability=_safe_probability(p.probability),
            label=p.label,
            attack_class=p.attack_class,
            explanation=None,
        )
        for p in persisted
    ]


@router.get("/inferences", response_model=list[schemas.InferenceResult])
async def list_inferences(
    limit: int = Query(50, ge=1, le=500),
    label: str | None = Query(None, pattern="^(benign|attack)$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> Any:
    stmt = select(Inference).order_by(Inference.timestamp.desc()).limit(limit)
    if label:
        stmt = stmt.where(Inference.label == label)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        schemas.InferenceResult(
            id=r.id,
            timestamp=r.timestamp,
            prediction=r.prediction,
            probability=_safe_probability(r.probability),
            label=r.label,
            attack_class=r.attack_class,
            explanation=None,
        )
        for r in rows
    ]


@router.get("/model/info", response_model=schemas.ModelInfo)
async def model_info_route(user: User = Depends(current_user)) -> Any:
    return schemas.ModelInfo(**inference.model_info())


@router.get("/drift/summary", response_model=schemas.DriftFeatureSummary)
async def drift_summary(
    feature: str = Query("serror_rate", min_length=1, max_length=64),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> Any:
    """Rolling stats for one numeric feature in recent stored inferences (drift / QA)."""
    s = await feature_drift_for_key(db, feature, limit=500)
    if s is None:
        return schemas.DriftFeatureSummary(
            feature=feature, status="insufficient_data", n_samples=0, stats={}
        )
    return schemas.DriftFeatureSummary(
        feature=feature,
        status="ok",
        n_samples=s.n_samples,
        stats=s.to_dict(),
    )
