"""SIEM ORM models: events, detection rules, alerts."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


def _mutable_list() -> list[str]:
    return []


def _mutable_dict() -> dict[str, Any]:
    return {}


class Event(Base):
    __tablename__ = "siem_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False, index=True, default=lambda: datetime.now(tz=timezone.utc)
    )
    source: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=_mutable_dict)
    parsed_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=_mutable_dict)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    tags_array: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=_mutable_list)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="event", cascade="all, delete-orphan")


class DetectionRule(Base):
    __tablename__ = "siem_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    query_dsl_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=_mutable_dict
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    attack_technique_ids_array: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=_mutable_list
    )
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=lambda: datetime.now(tz=timezone.utc)
    )

    alerts: Mapped[list["Alert"]] = relationship(back_populates="rule")


class Alert(Base):
    __tablename__ = "siem_alerts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("siem_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("siem_rules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, default=lambda: datetime.now(tz=timezone.utc)
    )
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    event: Mapped[Event] = relationship(back_populates="alerts")
    rule: Mapped["DetectionRule | None"] = relationship(back_populates="alerts")
