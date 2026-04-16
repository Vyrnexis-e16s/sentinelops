"""Append-only audit log with SHA-256 hash chain."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False, index=True, default=lambda: datetime.now(tz=timezone.utc)
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary(length=32), nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary(length=32), nullable=False, unique=True)
