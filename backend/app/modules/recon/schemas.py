"""Recon Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TargetKind = Literal["domain", "host", "cidr"]
JobKind = Literal["subdomain", "port", "cve", "webfuzz"]
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
