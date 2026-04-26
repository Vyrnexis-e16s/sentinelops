"""VAPT — unified surface metrics, optional LLM triage, saved briefs."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_user
from app.models.user import User
from app.modules.vapt.models import VaptBrief
from app.modules.vapt.schemas import BriefCreate, BriefOut, LlmSummarizeIn, LlmSummarizeOut, SurfaceOut
from app.modules.vapt.services import llm as llm_service
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
    """Call configured OpenAI-compatible endpoint with your assembled context. No key → 503."""
    try:
        summary, model = await llm_service.summarize_triage(
            context=payload.context, instruction=payload.instruction
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
        metadata={"model": model, "context_chars": len(payload.context)},
    )
    await db.commit()
    return LlmSummarizeOut(summary=summary, model=model)


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
) -> None:
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
