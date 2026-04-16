"""Tamper-evident audit log service with a SHA-256 hash chain."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import ZERO_HASH, audit_entry_hash, verify_audit_chain
from app.core.db import get_db
from app.core.logging import get_logger
from app.models.audit import AuditLog
from app.services.events import CHANNEL_AUDIT, publish

log = get_logger(__name__)


class AuditService:
    """Append-only audit ledger. Each row's hash commits to the previous row's hash."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _latest_hash(self) -> bytes:
        result = await self.db.execute(
            select(AuditLog.entry_hash).order_by(desc(AuditLog.timestamp)).limit(1)
        )
        row = result.scalar_one_or_none()
        return row if row is not None else ZERO_HASH

    async def append(
        self,
        *,
        actor_id: uuid.UUID | None,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Write a single audit row. Also publishes to the `audit.events` channel."""
        metadata = metadata or {}
        prev = await self._latest_hash()
        ts = datetime.now(tz=timezone.utc)
        payload: dict[str, Any] = {
            "timestamp": ts.isoformat(),
            "actor_id": str(actor_id) if actor_id else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": metadata,
        }
        entry_hash = audit_entry_hash(prev, payload)

        row = AuditLog(
            id=uuid.uuid4(),
            timestamp=ts,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata_json=metadata,
            prev_hash=prev,
            entry_hash=entry_hash,
        )
        self.db.add(row)
        await self.db.flush()

        log.info(
            "audit.append",
            audit_id=str(row.id),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_id=str(actor_id) if actor_id else None,
        )

        try:
            await publish(
                CHANNEL_AUDIT,
                {
                    "id": str(row.id),
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "timestamp": ts.isoformat(),
                    "actor_id": str(actor_id) if actor_id else None,
                },
            )
        except Exception as exc:  # pragma: no cover - best effort
            log.warning("audit.publish_failed", error=str(exc))

        return row

    async def verify_chain(self, limit: int = 1000) -> bool:
        """Verify the newest `limit` entries of the chain."""
        q = (
            select(AuditLog)
            .order_by(AuditLog.timestamp.asc())
            .limit(limit)
        )
        result = await self.db.execute(q)
        entries = [
            {
                "prev_hash": r.prev_hash,
                "entry_hash": r.entry_hash,
                "payload": {
                    "timestamp": r.timestamp.isoformat(),
                    "actor_id": str(r.actor_id) if r.actor_id else None,
                    "action": r.action,
                    "resource_type": r.resource_type,
                    "resource_id": r.resource_id,
                    "metadata": r.metadata_json,
                },
            }
            for r in result.scalars().all()
        ]
        return verify_audit_chain(entries)


async def audit_logger(db: AsyncSession = Depends(get_db)) -> AuditService:
    """FastAPI dependency: ``audit: AuditService = Depends(audit_logger)``."""
    return AuditService(db)
