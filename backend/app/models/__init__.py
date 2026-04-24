"""SQLAlchemy declarative base + re-export of all shared models.

Module-specific models live under their respective modules but are imported here
so Alembic's metadata picks up every table.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, mapped_column

# All concrete models are imported below so they register with Base.metadata
# regardless of which module imports `Base`.


class Base(DeclarativeBase):
    """Project-wide declarative base."""

    type_annotation_map: dict[Any, Any] = {  # noqa: RUF012
        datetime: DateTime(timezone=True),
        uuid.UUID: __import__("sqlalchemy").Uuid(as_uuid=True),
    }


# ------- shared --------
from app.models.audit import AuditLog  # noqa: E402,F401
from app.models.user import User  # noqa: E402,F401
from app.models.webauthn import WebAuthnCredential  # noqa: E402,F401

# ------- module models --------
from app.modules.ids.models import Inference  # noqa: E402,F401
from app.modules.recon.models import Finding, ReconJob, Target  # noqa: E402,F401
from app.modules.siem.models import (  # noqa: E402,F401
    Alert,
    DetectionRule,
    Event,
    Investigation,
    ThreatIoc,
)
from app.modules.vault.models import VaultAccessGrant, VaultObject  # noqa: E402,F401

__all__ = [
    "Base",
    "User",
    "WebAuthnCredential",
    "AuditLog",
    "Event",
    "DetectionRule",
    "Alert",
    "ThreatIoc",
    "Investigation",
    "Target",
    "ReconJob",
    "Finding",
    "Inference",
    "VaultObject",
    "VaultAccessGrant",
    "mapped_column",
]
