"""SIEM REST API: events, rules, alerts."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.db import get_db
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.core.security import current_user
from app.models.user import User
from app.modules.siem.models import Alert, DetectionRule, Event, ThreatIoc
from app.modules.siem.services import intel_enrich
from app.modules.siem.schemas import (
    AlertOut,
    AlertStatus,
    AlertUpdate,
    EventBulkIngest,
    EventIngest,
    EventOut,
    IngestResult,
    RuleCreate,
    RuleOut,
    RuleUpdate,
)
from app.modules.siem.services.detection import evaluate_many
from app.schemas.common import Paginated
from app.services.audit import AuditService, audit_logger
from app.services.events import CHANNEL_ALERTS, publish

log = get_logger(__name__)

router = APIRouter(prefix="/siem", tags=["siem"])

RULES_DIR = Path(__file__).parent / "rules"


# --------------------------------------------------------------------------- #
# Rule loading helpers                                                        #
# --------------------------------------------------------------------------- #


def load_starter_rules() -> list[dict[str, Any]]:
    """Load the shipped JSON rules at startup-time."""
    rules: list[dict[str, Any]] = []
    if not RULES_DIR.exists():
        return rules
    for path in sorted(RULES_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as fh:
            rules.append(json.load(fh))
    return rules


async def seed_starter_rules_if_empty(db: AsyncSession) -> int:
    existing = await db.execute(select(func.count(DetectionRule.id)))
    if existing.scalar_one() > 0:
        return 0
    inserted = 0
    for r in load_starter_rules():
        db.add(
            DetectionRule(
                id=uuid.uuid4(),
                name=r["name"],
                description=r.get("description", ""),
                query_dsl_json=r["query_dsl"],
                enabled=True,
                attack_technique_ids_array=list(r.get("attack_technique_ids") or []),
            )
        )
        inserted += 1
    await db.flush()
    return inserted


# --------------------------------------------------------------------------- #
# Ingestion + detection                                                       #
# --------------------------------------------------------------------------- #


async def _fetch_enabled_rules(db: AsyncSession) -> list[dict[str, Any]]:
    result = await db.execute(select(DetectionRule).where(DetectionRule.enabled.is_(True)))
    out: list[dict[str, Any]] = []
    for r in result.scalars().all():
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "query_dsl": r.query_dsl_json,
                "enabled": r.enabled,
                "attack_technique_ids": r.attack_technique_ids_array,
            }
        )
    return out


async def _ingest_one(
    payload: EventIngest,
    db: AsyncSession,
    rules: list[dict[str, Any]],
    actor_id: uuid.UUID,
    audit: AuditService,
) -> tuple[Event, int]:
    event = Event(
        id=uuid.uuid4(),
        timestamp=payload.timestamp or datetime.now(tz=timezone.utc),
        source=payload.source,
        raw_json=payload.raw,
        parsed_json=payload.parsed,
        severity=payload.severity,
        tags_array=payload.tags,
    )
    db.add(event)
    await db.flush()

    doc = {
        "source": payload.source,
        "severity": payload.severity,
        "tags": payload.tags,
        "raw": payload.raw,
        "parsed": payload.parsed,
    }
    alerts_created = 0
    matches = evaluate_many(doc, rules)
    for match in matches:
        rule_id = next((r["id"] for r in rules if r["name"] == match.rule_name), None)
        alert = Alert(
            id=uuid.uuid4(),
            event_id=event.id,
            rule_id=rule_id,
            score=match.score,
            status="new",
        )
        db.add(alert)
        alerts_created += 1
        try:
            await publish(
                CHANNEL_ALERTS,
                {
                    "id": str(alert.id),
                    "event_id": str(event.id),
                    "rule": match.rule_name,
                    "score": match.score,
                    "severity": match.severity,
                    "attack": match.technique_ids,
                    "kind": "detection",
                },
            )
        except Exception as exc:  # pragma: no cover - best effort
            log.warning("alert_publish_failed", error=str(exc))

    ioc_rows = (await db.execute(select(ThreatIoc.ioc_type, ThreatIoc.value))).all()
    if ioc_rows:
        known = {(t, v) for t, v in ioc_rows}
        cands = intel_enrich.collect_candidate_tokens(doc)
        hits = intel_enrich.find_ioc_hits(cands, known)
        if hits:
            seen: set[str] = set()
            for t, v in hits:
                key = f"{t}:{v}"
                if key in seen:
                    continue
                seen.add(key)
                tags = list(event.tags_array or [])
                for tag in (f"ioc:{t}", "ioc:match"):
                    if tag not in tags:
                        tags.append(tag)
                event.tags_array = tags
                a2 = Alert(
                    id=uuid.uuid4(),
                    event_id=event.id,
                    rule_id=None,
                    score=8.2,
                    status="new",
                )
                db.add(a2)
                alerts_created += 1
                try:
                    await publish(
                        CHANNEL_ALERTS,
                        {
                            "id": str(a2.id),
                            "event_id": str(event.id),
                            "rule": "threat.intel.ioc",
                            "score": 8.2,
                            "severity": "high",
                            "attack": ["T001"],
                            "kind": "threat_intel",
                        },
                    )
                except Exception as exc:  # pragma: no cover
                    log.warning("alert_publish_failed", error=str(exc))

    log.info(
        "event_ingested",
        event_id=str(event.id),
        source=payload.source,
        severity=payload.severity,
        alerts=alerts_created,
    )
    await audit.append(
        actor_id=actor_id,
        action="siem.event.ingest",
        resource_type="siem_event",
        resource_id=str(event.id),
        metadata={"source": payload.source, "alerts": alerts_created},
    )
    return event, alerts_created


@router.post("/events", response_model=IngestResult)
async def ingest_event(
    payload: EventIngest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> IngestResult:
    rules = await _fetch_enabled_rules(db)
    event, created = await _ingest_one(payload, db, rules, user.id, audit)
    await db.commit()
    return IngestResult(event_ids=[event.id], alerts_created=created)


@router.post("/events/bulk", response_model=IngestResult)
async def ingest_events_bulk(
    payload: EventBulkIngest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> IngestResult:
    rules = await _fetch_enabled_rules(db)
    ids: list[uuid.UUID] = []
    total_alerts = 0
    for p in payload.events:
        event, created = await _ingest_one(p, db, rules, user.id, audit)
        ids.append(event.id)
        total_alerts += created
    await db.commit()
    return IngestResult(event_ids=ids, alerts_created=total_alerts)


@router.get("/events", response_model=Paginated[EventOut])
async def list_events(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    source: str | None = None,
    severity: str | None = None,
) -> Paginated[EventOut]:
    q = select(Event)
    c = select(func.count(Event.id))
    if source:
        q = q.where(Event.source == source)
        c = c.where(Event.source == source)
    if severity:
        q = q.where(Event.severity == severity)
        c = c.where(Event.severity == severity)

    total = (await db.execute(c)).scalar_one()
    q = q.order_by(Event.timestamp.desc()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().all()
    return Paginated[EventOut](
        items=[EventOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


# --------------------------------------------------------------------------- #
# Rules                                                                       #
# --------------------------------------------------------------------------- #


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db), _: User = Depends(current_user)
) -> list[RuleOut]:
    rows = (await db.execute(select(DetectionRule).order_by(DetectionRule.name))).scalars().all()
    return [RuleOut.model_validate(r) for r in rows]


@router.post("/rules", response_model=RuleOut)
async def create_rule(
    payload: RuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> RuleOut:
    rule = DetectionRule(
        id=uuid.uuid4(),
        name=payload.name,
        description=payload.description,
        query_dsl_json=payload.query_dsl.model_dump(),
        enabled=payload.enabled,
        attack_technique_ids_array=payload.attack_technique_ids,
    )
    db.add(rule)
    await audit.append(
        actor_id=user.id,
        action="siem.rule.create",
        resource_type="siem_rule",
        resource_id=str(rule.id),
        metadata={"name": rule.name},
    )
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule)


@router.put("/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> RuleOut:
    rule = await db.get(DetectionRule, rule_id)
    if rule is None:
        raise NotFoundError("Rule not found")
    if payload.description is not None:
        rule.description = payload.description
    if payload.query_dsl is not None:
        rule.query_dsl_json = payload.query_dsl.model_dump()
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.attack_technique_ids is not None:
        rule.attack_technique_ids_array = payload.attack_technique_ids
    await audit.append(
        actor_id=user.id,
        action="siem.rule.update",
        resource_type="siem_rule",
        resource_id=str(rule.id),
        metadata=payload.model_dump(exclude_unset=True),
    )
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule)


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> dict[str, str]:
    rule = await db.get(DetectionRule, rule_id)
    if rule is None:
        raise NotFoundError("Rule not found")
    await db.delete(rule)
    await audit.append(
        actor_id=user.id,
        action="siem.rule.delete",
        resource_type="siem_rule",
        resource_id=str(rule_id),
    )
    await db.commit()
    return {"status": "deleted"}


# --------------------------------------------------------------------------- #
# Alerts                                                                      #
# --------------------------------------------------------------------------- #


@router.get("/alerts", response_model=Paginated[AlertOut])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    status: AlertStatus | None = None,
) -> Paginated[AlertOut]:
    q = select(Alert).options(selectinload(Alert.rule))
    c = select(func.count(Alert.id))
    if status:
        st = status
        q = q.where(Alert.status == st)
        c = c.where(Alert.status == st)
    total = (await db.execute(c)).scalar_one()
    q = q.order_by(Alert.created_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(q)).scalars().unique().all()
    items: list[AlertOut] = []
    for a in rows:
        items.append(
            AlertOut(
                id=a.id,
                event_id=a.event_id,
                rule_id=a.rule_id,
                rule_name=a.rule.name if a.rule else None,
                score=a.score,
                status=a.status,
                created_at=a.created_at,
                assigned_to_id=a.assigned_to_id,
                alert_kind="threat_intel" if a.rule_id is None else "detection",
            )
        )
    return Paginated[AlertOut](
        items=items, page=page, size=size, total=total
    )


@router.put("/alerts/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> AlertOut:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise NotFoundError("Alert not found")
    if payload.status is not None:
        alert.status = payload.status
    if payload.assigned_to_id is not None:
        alert.assigned_to_id = payload.assigned_to_id
    await audit.append(
        actor_id=user.id,
        action="siem.alert.update",
        resource_type="siem_alert",
        resource_id=str(alert.id),
        metadata=payload.model_dump(exclude_unset=True),
    )
    await db.commit()
    await db.refresh(alert)
    return AlertOut.model_validate(alert)
