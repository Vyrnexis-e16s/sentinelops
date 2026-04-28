"""Recon Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TargetKind = Literal["domain", "host", "cidr"]
JobKind = Literal[
    "subdomain",
    "port",
    "cve",
    "webfuzz",
    "dns",
    "httprobe",
    "http_headers",
    "tls_cert",
    "ct",
    "wellknown",
    "fingerprint",
    "ptr",
    "takeover",
    "axfr",
    "robots_sitemap",
    "js_endpoints",
    "cookie_audit",
    "tls_audit",
    "wayback",
]
JobStatus = Literal["queued", "running", "done", "failed"]


class TargetCreate(BaseModel):
    kind: TargetKind
    value: str = Field(..., min_length=1, max_length=255)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    value: str
    created_at: datetime
    owner_id: uuid.UUID


class JobCreate(BaseModel):
    target_id: uuid.UUID
    kind: JobKind
    params: dict[str, Any] = Field(default_factory=dict)


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    kind: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    result_json: dict[str, Any]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    job_id: uuid.UUID
    severity: str
    title: str
    description: str
    evidence_json: dict[str, Any]


# --------------------------------------------------------------------------- #
# Schedules                                                                   #
# --------------------------------------------------------------------------- #


class ScheduleCreate(BaseModel):
    target_id: uuid.UUID
    kind: JobKind
    interval_minutes: int = Field(60, ge=5, le=10_080)  # 5 minutes – 7 days
    enabled: bool = True
    params: dict[str, Any] = Field(default_factory=dict)


class ScheduleUpdate(BaseModel):
    interval_minutes: int | None = Field(None, ge=5, le=10_080)
    enabled: bool | None = None
    params: dict[str, Any] | None = None


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    kind: str
    interval_minutes: int
    enabled: bool
    params_json: dict[str, Any]
    last_run_at: datetime | None
    last_job_id: uuid.UUID | None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Diff                                                                        #
# --------------------------------------------------------------------------- #


class DiffEntry(BaseModel):
    name: str
    state: Literal["new", "removed", "stable"]


class DiffResult(BaseModel):
    target_id: uuid.UUID
    kind: str
    base_job_id: uuid.UUID | None
    head_job_id: uuid.UUID
    new_count: int
    removed_count: int
    stable_count: int
    entries: list[DiffEntry]


# --------------------------------------------------------------------------- #
# Asset graph                                                                 #
# --------------------------------------------------------------------------- #


class GraphNode(BaseModel):
    id: str
    label: str
    type: Literal["target", "subdomain", "ip", "asn", "cve", "service"]
    severity: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class GraphOut(BaseModel):
    target_id: uuid.UUID
    nodes: list[GraphNode]
    edges: list[GraphEdge]
