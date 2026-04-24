"""SIEM Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
AlertStatus = Literal["new", "ack", "resolved", "false_positive"]


# --------------------------------------------------------------------------- #
# Events                                                                      #
# --------------------------------------------------------------------------- #


class EventIngest(BaseModel):
    timestamp: datetime | None = None
    source: str = Field(..., min_length=1, max_length=120)
    raw: dict[str, Any] = Field(default_factory=dict)
    parsed: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = "info"
    tags: list[str] = Field(default_factory=list)


class EventBulkIngest(BaseModel):
    events: list[EventIngest] = Field(..., min_length=1, max_length=5000)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    source: str
    raw_json: dict[str, Any]
    parsed_json: dict[str, Any]
    severity: str
    tags_array: list[str]


# --------------------------------------------------------------------------- #
# Rules                                                                       #
# --------------------------------------------------------------------------- #


class RuleCondition(BaseModel):
    field: str
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte", "contains", "regex", "in", "exists"]
    value: Any | None = None


class RuleDSL(BaseModel):
    all_of: list[RuleCondition] = Field(default_factory=list)
    any_of: list[RuleCondition] = Field(default_factory=list)
    none_of: list[RuleCondition] = Field(default_factory=list)
    score: float = Field(1.0, ge=0.0, le=10.0)
    severity: Severity = "medium"


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    query_dsl: RuleDSL
    enabled: bool = True
    attack_technique_ids: list[str] = Field(default_factory=list)


class RuleUpdate(BaseModel):
    description: str | None = None
    query_dsl: RuleDSL | None = None
    enabled: bool | None = None
    attack_technique_ids: list[str] | None = None


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    query_dsl_json: dict[str, Any]
    enabled: bool
    attack_technique_ids_array: list[str]
    created_at: datetime


# --------------------------------------------------------------------------- #
# Alerts                                                                      #
# --------------------------------------------------------------------------- #


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assigned_to_id: uuid.UUID | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_id: uuid.UUID
    rule_id: uuid.UUID | None
    rule_name: str | None = None
    score: float
    status: str
    created_at: datetime
    assigned_to_id: uuid.UUID | None
    alert_kind: str | None = None  # e.g. "detection" | "threat_intel"


class IngestResult(BaseModel):
    event_ids: list[uuid.UUID]
    alerts_created: int


# --- Sigma + threat intel + cases -------------------------------------------------


class SigmaCompileRequest(BaseModel):
    yaml: str = Field(..., min_length=4)
    field_prefix: str = "parsed"


class SigmaCompileResult(BaseModel):
    title: str
    description: str
    query_dsl: RuleDSL


class StixBundleIn(BaseModel):
    """STIX 2.1 bundle or a JSON list of STIX objects from a TAXII poll."""

    bundle: dict[str, Any] | None = None
    objects: list[dict[str, Any]] | None = None


class ThreatIocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ioc_type: str
    value: str
    stix_id: str | None
    source: str
    created_at: datetime


class UebaSourceOut(BaseModel):
    source: str
    count_24h: int
    count_30d: int
    daily_baseline: float
    z_score: float
    deviates: bool


class UebaSummaryOut(BaseModel):
    sources: list[UebaSourceOut]


class InvestigationCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: str = ""
    state: str = "open"
    alert_ids: list[uuid.UUID] = Field(default_factory=list)


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str
    state: str
    owner_id: uuid.UUID | None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class InvestigationUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    state: str | None = None
    owner_id: uuid.UUID | None = None
    alert_ids: list[uuid.UUID] | None = None
