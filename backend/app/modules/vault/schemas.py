"""Vault request / response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class VaultObjectOut(BaseModel):
    id: uuid.UUID
    name: str
    size: int
    mime_type: str
    created_at: datetime


class ShareRequest(BaseModel):
    grantee_id: uuid.UUID
    permissions: str = Field("read", pattern="^(read|read_write)$")
    expires_at: datetime | None = None


class GrantOut(BaseModel):
    id: uuid.UUID
    object_id: uuid.UUID
    grantee_id: uuid.UUID
    created_at: datetime
    expires_at: datetime | None
    permissions: str


class AuditEntryOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    metadata: dict
    entry_hash: str
