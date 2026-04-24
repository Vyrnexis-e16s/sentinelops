"""SIEM: Sigma, STIX threat intel, UEBA summary, case investigations."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import NotFoundError
from app.core.security import current_user
from app.models import User
from app.modules.siem.models import Alert, DetectionRule, Investigation, ThreatIoc
from app.modules.siem.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationUpdate,
    RuleCreate,
    RuleOut,
    SigmaCompileRequest,
    SigmaCompileResult,
    StixBundleIn,
    ThreatIocOut,
    UebaSourceOut,
    UebaSummaryOut,
)
from app.modules.siem.services.sigma import compile_sigma_yaml
from app.modules.siem.services.stix_ingest import (
    extract_from_bundle,
    synthetic_rows_from_stix2_objects,
)
from app.modules.siem.services.ueba import build_source_ueba
from app.services.audit import AuditService, audit_logger

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/siem", tags=["siem"])


@router.post("/sigma/compile", response_model=SigmaCompileResult)
async def compile_sigma(
    body: SigmaCompileRequest,
    _: User = Depends(current_user),
) -> SigmaCompileResult:
    try:
        title, desc, dsl = compile_sigma_yaml(body.yaml, field_prefix=body.field_prefix)
    except Exception as exc:
        log.warning("sigma_compile_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return SigmaCompileResult(title=title, description=desc, query_dsl=dsl)


@router.post("/threat-intel/stix", response_model=list[ThreatIocOut])
async def ingest_stix(
    body: StixBundleIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> list[ThreatIocOut]:
    if not body.bundle and not body.objects:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either bundle (STIX bundle) or objects (list of STIX objects).",
        )
    row_dicts: list[dict[str, Any]] = []
    if body.bundle is not None:
        row_dicts.extend(extract_from_bundle(body.bundle))
    if body.objects is not None:
        row_dicts.extend(synthetic_rows_from_stix2_objects(body.objects))

    added: list[ThreatIoc] = []
    for r in row_dicts:
        v = str(r.get("value", "")).strip()
        it = str(r.get("ioc_type", "string"))
        if not v:
            continue
        ex = (
            await db.execute(select(ThreatIoc).where(ThreatIoc.ioc_type == it, ThreatIoc.value == v))
        ).scalar_one_or_none()
        if ex is not None:
            continue
        ioc = ThreatIoc(
            id=uuid.uuid4(),
            ioc_type=it,
            value=v,
            stix_id=r.get("stix_id"),
            source="stix2",
            metadata_json=r.get("metadata") or {},
        )
        db.add(ioc)
        added.append(ioc)

    await db.flush()
    await audit.append(
        actor_id=user.id,
        action="siem.stix.ingest",
        resource_type="threat_intel",
        resource_id="batch",
        metadata={"ingested": len(added)},
    )
    await db.commit()
    return [ThreatIocOut.model_validate(x) for x in added]


@router.get("/threat-intel/iocs", response_model=list[ThreatIocOut])
async def list_iocs(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
    limit: int = 200,
) -> list[ThreatIocOut]:
    q = select(ThreatIoc).order_by(ThreatIoc.created_at.desc()).limit(min(limit, 2000))
    rows = (await db.execute(q)).scalars().all()
    return [ThreatIocOut.model_validate(r) for r in rows]


@router.get("/ueba/summary", response_model=UebaSummaryOut)
async def ueba_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> UebaSummaryOut:
    src = await build_source_ueba(db)
    return UebaSummaryOut(
        sources=[UebaSourceOut(**s.model_dump()) for s in src],
    )


@router.post(
    "/rules/from-sigma",
    response_model=RuleOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule_from_sigma(
    body: SigmaCompileRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> RuleOut:
    try:
        title, desc, dsl = compile_sigma_yaml(body.yaml, field_prefix=body.field_prefix)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    r = await db.execute(select(DetectionRule).where(DetectionRule.name == title))
    if r.scalar_one_or_none() is not None:
        title = f"{title}-{uuid.uuid4().hex[:8]}"
    model = RuleCreate(
        name=title[:200],
        description=desc,
        query_dsl=dsl,
        enabled=True,
        attack_technique_ids=[],
    )
    rule = DetectionRule(
        id=uuid.uuid4(),
        name=model.name,
        description=model.description,
        query_dsl_json=model.query_dsl.model_dump(),
        enabled=model.enabled,
        attack_technique_ids_array=model.attack_technique_ids,
    )
    db.add(rule)
    await audit.append(
        actor_id=user.id,
        action="siem.rule.from_sigma",
        resource_type="siem_rule",
        resource_id=str(rule.id),
        metadata={"name": rule.name},
    )
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule)


def _parse_alert_ids(stored: list[str]) -> list[uuid.UUID]:
    out: list[uuid.UUID] = []
    for s in stored:
        try:
            out.append(uuid.UUID(str(s)))
        except ValueError:
            continue
    return out


@router.post(
    "/investigations",
    response_model=InvestigationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_investigation(
    body: InvestigationCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> InvestigationOut:
    for aid in body.alert_ids:
        if await db.get(Alert, aid) is None:
            raise NotFoundError(f"Alert {aid} not found")
    inv = Investigation(
        id=uuid.uuid4(),
        title=body.title,
        description=body.description,
        state=body.state,
        owner_id=user.id,
        alert_ids_array=[str(x) for x in body.alert_ids],
    )
    db.add(inv)
    await audit.append(
        actor_id=user.id,
        action="siem.investigation.create",
        resource_type="siem_investigation",
        resource_id=str(inv.id),
        metadata={"title": inv.title},
    )
    await db.commit()
    await db.refresh(inv)
    return InvestigationOut(
        id=inv.id,
        title=inv.title,
        description=inv.description,
        state=inv.state,
        owner_id=inv.owner_id,
        alert_ids=_parse_alert_ids(inv.alert_ids_array),
        created_at=inv.created_at,
        updated_at=inv.updated_at,
    )


@router.get("/investigations", response_model=list[InvestigationOut])
async def list_investigations(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> list[InvestigationOut]:
    rows = (await db.execute(select(Investigation).order_by(Investigation.created_at.desc()))).scalars().all()
    return [
        InvestigationOut(
            id=r.id,
            title=r.title,
            description=r.description,
            state=r.state,
            owner_id=r.owner_id,
            alert_ids=_parse_alert_ids(r.alert_ids_array),
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


@router.get("/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(
    inv_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> InvestigationOut:
    r = await db.get(Investigation, inv_id)
    if r is None:
        raise NotFoundError("Investigation not found")
    return InvestigationOut(
        id=r.id,
        title=r.title,
        description=r.description,
        state=r.state,
        owner_id=r.owner_id,
        alert_ids=_parse_alert_ids(r.alert_ids_array),
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.put("/investigations/{inv_id}", response_model=InvestigationOut)
async def update_investigation(
    inv_id: uuid.UUID,
    body: InvestigationUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> InvestigationOut:
    r = await db.get(Investigation, inv_id)
    if r is None:
        raise NotFoundError("Investigation not found")
    if body.title is not None:
        r.title = body.title
    if body.description is not None:
        r.description = body.description
    if body.state is not None:
        r.state = body.state
    if body.owner_id is not None:
        r.owner_id = body.owner_id
    if body.alert_ids is not None:
        for aid in body.alert_ids:
            if await db.get(Alert, aid) is None:
                raise NotFoundError(f"Alert {aid} not found")
        r.alert_ids_array = [str(x) for x in body.alert_ids]
    r.updated_at = datetime.now(tz=timezone.utc)
    await audit.append(
        actor_id=user.id,
        action="siem.investigation.update",
        resource_type="siem_investigation",
        resource_id=str(r.id),
        metadata=body.model_dump(exclude_unset=True),
    )
    await db.commit()
    await db.refresh(r)
    return InvestigationOut(
        id=r.id,
        title=r.title,
        description=r.description,
        state=r.state,
        owner_id=r.owner_id,
        alert_ids=_parse_alert_ids(r.alert_ids_array),
        created_at=r.created_at,
        updated_at=r.updated_at,
    )
