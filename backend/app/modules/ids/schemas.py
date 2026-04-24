"""IDS request / response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class InferenceRequest(BaseModel):
    """A single flow's features. Missing values are imputed with training medians."""

    features: dict[str, float | int | str] = Field(default_factory=dict)
    explain: bool = Field(
        default=False,
        description="If true, return a tree-model feature weight proxy (not full SHAP).",
    )


class BulkInferenceRequest(BaseModel):
    flows: list[dict[str, float | int | str]]


class InferenceResult(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    prediction: str
    probability: float
    label: str
    attack_class: str | None = None
    explanation: dict[str, Any] | None = None


class ModelInfo(BaseModel):
    trained_at: datetime | None
    accuracy: float | None
    feature_count: int
    feature_list: list[str]
    classes: list[str]
    artifact_present: bool
    artifact_path: str
    notes: str | None = None


class DriftFeatureSummary(BaseModel):
    feature: str
    status: str
    n_samples: int
    stats: dict[str, Any] = Field(default_factory=dict)
