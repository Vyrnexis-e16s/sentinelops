"""VAPT — unified surface metrics, optional LLM triage, saved briefs, TTP memory, graph export."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from starlette.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_user
from app.models.user import User
from app.modules.recon.models import Target as ReconTarget
from app.modules.vapt.models import VaptAnalystFeedback, VaptBrief, VaptGraphEdge, VaptTtpMemory
from app.modules.vapt.schemas import (
    AnalystFeedbackCreate,
    AnalystFeedbackOut,
    BriefCreate,
    BriefOut,
    CypherExportOut,
    GraphEdgeCreate,
    GraphEdgeOut,
    LlmSummarizeIn,
    LlmSummarizeOut,
    MitreFoundationOut,
    ReconOrchestrateIn,
    ReconOrchestrateOut,
    SurfaceOut,
    TtpMemoryOut,
    TtpMemoryUpsert,
)
from app.modules.vapt import mitre_data
from app.modules.vapt.services import llm as llm_service
from app.modules.vapt.services.cypher_export import build_cypher_export
from app.modules.vapt.services.recon_batch import enqueue_recon_kinds
from app.modules.vapt.services.surface import build_surface
from app.schemas.common import Paginated
from app.services.audit import AuditService, audit_logger

router = APIRouter(prefix="/vapt", tags=["vapt"])


@router.get("/surface", response_model=SurfaceOut)
async def vapt_surface(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> SurfaceOut:
    """Real-time roll-up from production tables (not mocked)."""
    data = await build_surface(db, user.id)
    return SurfaceOut.model_validate(data)


@router.post("/llm/summarize", response_model=LlmSummarizeOut)
async def vapt_llm_summarize(
    payload: LlmSummarizeIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> LlmSummarizeOut:
    """Call OpenAI-compatible endpoint (or two-step local cascade: draft + refine)."""
    try:
        summary, model = await llm_service.summarize_triage(
            context=payload.context,
            instruction=payload.instruction,
            inject_mitre_context=payload.inject_mitre_context,
            use_cascade=payload.use_cascade,
        )
    except llm_service.LlmNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except llm_service.LlmUpstreamError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    await audit.append(
        actor_id=user.id,
        action="vapt.llm.summarize",
        resource_type="vapt",
        resource_id="llm",
        metadata={
            "model": model,
            "context_chars": len(payload.context),
            "mitre": payload.inject_mitre_context,
            "cascade": payload.use_cascade and ("→" in model or "cascade" in model),
        },
    )
    await db.commit()
    return LlmSummarizeOut(summary=summary, model=model)


@router.get("/mitre/foundation", response_model=MitreFoundationOut)
async def vapt_mitre_foundation(
    user: User = Depends(current_user),  # noqa: ARG001
) -> MitreFoundationOut:
    return MitreFoundationOut(items=mitre_data.load_mitre_foundation())


@router.get("/ttp", response_model=Paginated[TtpMemoryOut])
async def list_ttp_memory(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
) -> Paginated[TtpMemoryOut]:
    q = select(VaptTtpMemory).where(VaptTtpMemory.owner_id == user.id)
    total = int(
        (await db.execute(select(func.count(VaptTtpMemory.id)).where(VaptTtpMemory.owner_id == user.id)))
        .scalar_one()
    )
    rows = (
        (await db.execute(q.order_by(VaptTtpMemory.updated_at.desc()).offset((page - 1) * size).limit(size)))
        .scalars()
        .all()
    )
    return Paginated[TtpMemoryOut](
        items=[TtpMemoryOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


@router.put("/ttp", response_model=TtpMemoryOut)
async def upsert_ttp_memory(
    payload: TtpMemoryUpsert,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> TtpMemoryOut:
    res = await db.execute(
        select(VaptTtpMemory).where(
            VaptTtpMemory.owner_id == user.id, VaptTtpMemory.technique_id == payload.technique_id
        )
    )
    row = res.scalars().first()
    now = datetime.now(tz=timezone.utc)
    if row is None:
        row = VaptTtpMemory(
            id=uuid.uuid4(),
            owner_id=user.id,
            technique_id=payload.technique_id,
            name=(payload.name or "")[:500],
            body=payload.body,
            narrative_json=dict(payload.narrative or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        act = "vapt.ttp.create"
    else:
        row.name = (payload.name or row.name)[:500]
        row.body = payload.body
        row.narrative_json = dict(payload.narrative or {})
        row.updated_at = now
        act = "vapt.ttp.update"
    await audit.append(
        actor_id=user.id,
        action=act,
        resource_type="vapt_ttp_memory",
        resource_id=payload.technique_id,
        metadata={"name": (payload.name or "")[:120]},
    )
    await db.commit()
    await db.refresh(row)
    return TtpMemoryOut.model_validate(row)


@router.delete("/ttp/{row_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ttp_memory(
    row_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> Response:
    r = await db.get(VaptTtpMemory, row_id)
    if r is None or r.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TTP memory not found")
    await db.delete(r)
    await audit.append(
        actor_id=user.id,
        action="vapt.ttp.delete",
        resource_type="vapt_ttp_memory",
        resource_id=str(row_id),
        metadata={"technique_id": r.technique_id},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/graph/edges", response_model=Paginated[GraphEdgeOut])
async def list_graph_edges(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> Paginated[GraphEdgeOut]:
    q = select(VaptGraphEdge).where(VaptGraphEdge.owner_id == user.id)
    total = int(
        (await db.execute(select(func.count(VaptGraphEdge.id)).where(VaptGraphEdge.owner_id == user.id)))
        .scalar_one()
    )
    rows = (
        (await db.execute(q.order_by(VaptGraphEdge.created_at.desc()).offset((page - 1) * size).limit(size)))
        .scalars()
        .all()
    )
    return Paginated[GraphEdgeOut](
        items=[GraphEdgeOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


@router.post("/graph/edges", response_model=GraphEdgeOut, status_code=status.HTTP_201_CREATED)
async def create_graph_edge(
    payload: GraphEdgeCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> GraphEdgeOut:
    row = VaptGraphEdge(
        id=uuid.uuid4(),
        owner_id=user.id,
        from_technique_id=payload.from_technique_id,
        to_technique_id=payload.to_technique_id,
        relation=(payload.relation or "related")[:120],
        note=payload.note,
    )
    db.add(row)
    await audit.append(
        actor_id=user.id,
        action="vapt.graph.edge.create",
        resource_type="vapt_graph_edge",
        resource_id=str(row.id),
        metadata={"from": payload.from_technique_id, "to": payload.to_technique_id},
    )
    await db.commit()
    await db.refresh(row)
    return GraphEdgeOut.model_validate(row)


@router.delete("/graph/edges/{edge_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_graph_edge(
    edge_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> Response:
    r = await db.get(VaptGraphEdge, edge_id)
    if r is None or r.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Edge not found")
    await db.delete(r)
    await audit.append(
        actor_id=user.id,
        action="vapt.graph.edge.delete",
        resource_type="vapt_graph_edge",
        resource_id=str(edge_id),
        metadata={},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/graph/cypher", response_model=CypherExportOut)
async def export_graph_cypher(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> CypherExportOut:
    ttp_rows = (await db.execute(select(VaptTtpMemory).where(VaptTtpMemory.owner_id == user.id))).scalars().all()
    edge_rows = (await db.execute(select(VaptGraphEdge).where(VaptGraphEdge.owner_id == user.id))).scalars().all()
    cypher, n, e = build_cypher_export(ttps=ttp_rows, edges=edge_rows)
    return CypherExportOut(cypher=cypher, node_count=n, edge_count=e)


@router.get("/feedback", response_model=Paginated[AnalystFeedbackOut])
async def list_analyst_feedback(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(30, ge=1, le=200),
) -> Paginated[AnalystFeedbackOut]:
    q = select(VaptAnalystFeedback).where(VaptAnalystFeedback.owner_id == user.id)
    total = int(
        (
            await db.execute(
                select(func.count(VaptAnalystFeedback.id)).where(VaptAnalystFeedback.owner_id == user.id)
            )
        ).scalar_one()
    )
    rows = (
        (
            await db.execute(
                q.order_by(VaptAnalystFeedback.created_at.desc()).offset((page - 1) * size).limit(size)
            )
        )
        .scalars()
        .all()
    )
    return Paginated[AnalystFeedbackOut](
        items=[AnalystFeedbackOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


@router.post("/feedback", response_model=AnalystFeedbackOut, status_code=status.HTTP_201_CREATED)
async def create_analyst_feedback(
    payload: AnalystFeedbackCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> AnalystFeedbackOut:
    row = VaptAnalystFeedback(
        id=uuid.uuid4(),
        owner_id=user.id,
        ref_type=payload.ref_type,
        ref_key=(payload.ref_key or "")[:64],
        body=payload.body,
    )
    db.add(row)
    await audit.append(
        actor_id=user.id,
        action="vapt.feedback.create",
        resource_type="vapt_analyst_feedback",
        resource_id=str(row.id),
        metadata={"ref_type": payload.ref_type},
    )
    await db.commit()
    await db.refresh(row)
    return AnalystFeedbackOut.model_validate(row)


@router.delete("/feedback/{fb_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analyst_feedback(
    fb_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> Response:
    r = await db.get(VaptAnalystFeedback, fb_id)
    if r is None or r.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback not found")
    await db.delete(r)
    await audit.append(
        actor_id=user.id,
        action="vapt.feedback.delete",
        resource_type="vapt_analyst_feedback",
        resource_id=str(fb_id),
        metadata={},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/recon/orchestrate", response_model=ReconOrchestrateOut)
async def vapt_recon_orchestrate(
    payload: ReconOrchestrateIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> ReconOrchestrateOut:
    """Enqueue multiple recon jobs for one target (allowlisted). No exploitation — same workers as /recon/jobs."""
    tval = (payload.target or "").strip()
    jobs = await enqueue_recon_kinds(
        db,
        user,
        target_value=tval,
        kinds=payload.kinds,
        default_params=dict(payload.default_params or {}),
        per_kind_params=payload.per_kind_params,
        audit=audit,
    )
    res_tgt = await db.execute(
        select(ReconTarget).where(ReconTarget.owner_id == user.id, ReconTarget.value == tval)
    )
    tgt = res_tgt.scalars().first()
    if tgt is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Target missing after enqueue")
    return ReconOrchestrateOut(jobs=jobs, target_id=str(tgt.id))


@router.get("/briefs", response_model=Paginated[BriefOut])
async def list_briefs(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> Paginated[BriefOut]:
    q = select(VaptBrief).where(VaptBrief.owner_id == user.id)
    total = int(
        (await db.execute(select(func.count(VaptBrief.id)).where(VaptBrief.owner_id == user.id)))
        .scalar_one()
    )
    rows = (
        (
            await db.execute(
                q.order_by(VaptBrief.created_at.desc()).offset((page - 1) * size).limit(size)
            )
        )
        .scalars()
        .all()
    )
    return Paginated[BriefOut](
        items=[BriefOut.model_validate(r) for r in rows], page=page, size=size, total=total
    )


@router.post("/briefs", response_model=BriefOut, status_code=status.HTTP_201_CREATED)
async def create_brief(
    payload: BriefCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> BriefOut:
    row = VaptBrief(
        id=uuid.uuid4(),
        title=payload.title,
        body=payload.body,
        owner_id=user.id,
    )
    db.add(row)
    await audit.append(
        actor_id=user.id,
        action="vapt.brief.create",
        resource_type="vapt_brief",
        resource_id=str(row.id),
        metadata={"title": payload.title[:120]},
    )
    await db.commit()
    await db.refresh(row)
    return BriefOut.model_validate(row)


@router.delete("/briefs/{brief_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_brief(
    brief_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
) -> Response:
    r = await db.get(VaptBrief, brief_id)
    if r is None or r.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brief not found")
    await db.delete(r)
    await audit.append(
        actor_id=user.id,
        action="vapt.brief.delete",
        resource_type="vapt_brief",
        resource_id=str(brief_id),
        metadata={},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
