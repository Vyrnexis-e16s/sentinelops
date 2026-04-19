"""IDS ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


def _empty_features() -> dict[str, Any]:
    return {}


class Inference(Base):
    __tablename__ = "ids_inferences"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        nullable=False, index=True, default=lambda: datetime.now(tz=timezone.utc)
    )
    features_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=_empty_features
    )
    prediction: Mapped[str] = mapped_column(String(48), nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    label: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    attack_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
