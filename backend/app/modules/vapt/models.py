"""ORM: VAPT briefs, analyst TTP notes, simple graph edges, feedback."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.orm_base import Base


def _ts() -> datetime:
    return datetime.now(tz=timezone.utc)


def _empty() -> dict[str, Any]:
    return {}


class VaptBrief(Base):
    __tablename__ = "vapt_briefs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, index=True)


class VaptTtpMemory(Base):
    """Per-user notes keyed by MITRE technique id (analyst “memory”, not auto-learned)."""

    __tablename__ = "vapt_ttp_memory"
    __table_args__ = (UniqueConstraint("owner_id", "technique_id", name="uq_vapt_ttp_owner_technique"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    narrative_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=_empty)
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, index=True)
    updated_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, onupdate=_ts, index=True)


class VaptGraphEdge(Base):
    """Directed edges between techniques (analyst-curated; exportable to Cypher for Neo4j)."""

    __tablename__ = "vapt_graph_edges"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_technique_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    to_technique_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    relation: Mapped[str] = mapped_column(String(120), nullable=False, default="related")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, index=True)


class VaptAnalystFeedback(Base):
    """Short feedback tied to a TTP, edge, or free-form scope."""

    __tablename__ = "vapt_analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ref_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ref_key: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, index=True)
