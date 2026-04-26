"""ORM: saved VAPT briefs (executive summaries / triage notes)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.orm_base import Base


def _ts() -> datetime:
    return datetime.now(tz=timezone.utc)


class VaptBrief(Base):
    __tablename__ = "vapt_briefs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=_ts, index=True)
