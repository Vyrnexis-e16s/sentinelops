"""Aggregated re-export of every SQLAlchemy model.

Alembic's ``target_metadata = Base.metadata`` only sees tables whose classes
have been imported at least once. This module imports every model so Alembic
always has the full metadata when it is loaded. Individual modules should
import ``Base`` directly from :mod:`app.models.base` to avoid circular-import
issues with this aggregator.
"""
from __future__ import annotations

from sqlalchemy.orm import mapped_column

from app.core.orm_base import Base
from app.models.audit import AuditLog
from app.models.user import User
from app.models.webauthn import WebAuthnCredential
from app.modules.ids.models import Inference
from app.modules.recon.models import Finding, ReconJob, Target
from app.modules.siem.models import (
    Alert,
    DetectionRule,
    Event,
    Investigation,
    ThreatIoc,
)
from app.modules.vault.models import VaultAccessGrant, VaultObject
from app.modules.vapt.models import VaptBrief

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
    "VaptBrief",
    "mapped_column",
]
