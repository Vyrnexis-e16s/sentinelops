"""VAPT API schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.modules.vapt.mitre_ids import is_valid_mitre_technique_id


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
    inject_mitre_context: bool = Field(
        default=False,
        description="Append a curated MITRE technique reference list to the system prompt (no live MITRE API call).",
    )
    use_cascade: bool = Field(
        default=True,
        description="If the server has SENTINELOPS_LLM_DRAFT_MODEL set, run draft then refine; set false for a single call.",
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


# --- TTP memory / graph (analyst, not self-training) ---


class TtpMemoryUpsert(BaseModel):
    technique_id: str = Field(..., min_length=5, max_length=32)
    name: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=200_000)
    narrative: dict[str, Any] = Field(default_factory=dict)

    @field_validator("technique_id")
    @classmethod
    def _technique_id(cls, v: str) -> str:
        t = v.strip()
        if not is_valid_mitre_technique_id(t):
            raise ValueError("technique_id must look like T1234 or T1234.001")
        return t


class TtpMemoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    technique_id: str
    name: str
    body: str
    narrative: dict[str, Any] = Field(validation_alias="narrative_json", serialization_alias="narrative")
    created_at: datetime
    updated_at: datetime


class GraphEdgeCreate(BaseModel):
    from_technique_id: str = Field(..., min_length=5, max_length=32)
    to_technique_id: str = Field(..., min_length=5, max_length=32)
    relation: str = Field(default="related", min_length=1, max_length=120)
    note: str = Field(default="", max_length=50_000)

    @field_validator("from_technique_id", "to_technique_id")
    @classmethod
    def _tid(cls, v: str) -> str:
        t = v.strip()
        if not is_valid_mitre_technique_id(t):
            raise ValueError("technique ids must look like T1234 or T1234.001")
        return t


class GraphEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    from_technique_id: str
    to_technique_id: str
    relation: str
    note: str
    created_at: datetime


class CypherExportOut(BaseModel):
    """Text you can paste into a Neo4j browser; does not require Neo4j to use the product."""

    cypher: str
    node_count: int
    edge_count: int


class MitreFoundationOut(BaseModel):
    items: list[dict[str, str]]


class AnalystFeedbackCreate(BaseModel):
    ref_type: Literal["ttp", "edge", "brief", "other"]
    ref_key: str = Field(default="", max_length=64)
    body: str = Field(..., min_length=1, max_length=20_000)


class AnalystFeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ref_type: str
    ref_key: str
    body: str
    created_at: datetime


class ReconOrchestrateIn(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    kinds: list[str] = Field(..., min_length=1, max_length=32)
    default_params: dict[str, Any] = Field(default_factory=dict)
    per_kind_params: dict[str, dict[str, Any]] | None = None


class ReconOrchestrateOut(BaseModel):
    jobs: list[dict[str, str]]
    target_id: str
