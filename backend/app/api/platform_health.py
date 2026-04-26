"""Module-level health: DB, broker, and IDS model availability."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.redis import init_redis
from app.modules.ids.services import inference

router = APIRouter(prefix="/platform", tags=["ops"])


@router.get("/status")
async def platform_status(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Lightweight check that core dependencies respond (no auth — lab only)."""
    database = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        database = "error"

    redis = "ok"
    try:
        r = await init_redis()
        await r.ping()
    except Exception:  # noqa: BLE001
        redis = "error"

    ids_model = "ready" if inference.is_available() else "missing"

    return {
        "database": database,
        "redis": redis,
        "ids_model": ids_model,
        "modules": ["auth", "siem", "recon", "ids", "vault", "intel", "websockets"],
    }
