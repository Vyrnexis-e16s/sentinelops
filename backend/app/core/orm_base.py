"""SQLAlchemy declarative base.

Lives outside :mod:`app.models` so ORM classes under ``app.modules.*`` can
import ``Base`` without forcing Python to execute ``app.models.__init__``,
which re-imports every module's models for Alembic's benefit and would
otherwise create a circular-import when a module is imported standalone
(e.g. by the Celery worker entry point).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide declarative base."""

    type_annotation_map: dict[Any, Any] = {  # noqa: RUF012
        datetime: DateTime(timezone=True),
        uuid.UUID: Uuid(as_uuid=True),
    }
