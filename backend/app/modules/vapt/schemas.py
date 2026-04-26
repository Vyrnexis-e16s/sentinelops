"""VAPT API schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SurfaceOut(BaseModel):
    """Aggregated live counts for the VAPT command view."""

    siem_alerts_new: int
    siem_alerts_ack: int
    siem_events_24h: int
    recon_jobs_queued: int
    recon_jobs_running: int
    recon_findings_total: int
    ids_inferences_24h: int
    ids_attacks_24h: int
    vault_files: int
    investigations_open: int


class LlmSummarizeIn(BaseModel):
    context: str = Field(..., min_length=1, max_length=200_000)
    instruction: str = Field(
        default=(
            "You are a senior security assessor. Given raw telemetry and findings, "
            "produce a concise executive summary: top risks, MITRE-relevant themes, "
            "and recommended next steps. No prose fluff; use bullet lists where helpful."
        ),
        max_length=4000,
    )


class LlmSummarizeOut(BaseModel):
    summary: str
    model: str


class BriefCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    body: str = Field(..., min_length=1, max_length=500_000)


class BriefOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    body: str
    created_at: datetime
