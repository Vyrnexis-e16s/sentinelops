"""WebSocket: Redis SIEM alert channel → browser (auth via query ``token``)."""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketException
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.core.db import get_session_factory
from app.core.security import AuthError, decode_access_token
from app.models import User
from app.services.events import CHANNEL_ALERTS, subscribe

log = structlog.get_logger(__name__)
router = APIRouter(tags=["siem"])


@router.websocket("/alerts")
async def alerts_stream(websocket: WebSocket, token: str | None = Query(None)) -> None:
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return
    try:
        claims = decode_access_token(token)
        user_id = uuid.UUID(str(claims.get("sub")))
    except (AuthError, ValueError) as exc:
        log.warning("ws_auth_failed", error=str(exc))
        await websocket.close(code=1008, reason="invalid token")
        return

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        await websocket.close(code=1008, reason="inactive user")
        return

    await websocket.accept()
    try:
        async for msg in subscribe(CHANNEL_ALERTS):
            if not isinstance(msg, dict):
                continue
            try:
                await websocket.send_json(msg)
            except WebSocketException:
                break
    except (WebSocketDisconnect, ConnectionError, OSError):
        log.debug("ws_alerts_client_gone", user_id=str(user_id))
    except Exception as exc:  # pragma: no cover
        log.exception("ws_alerts_error", error=str(exc))
        try:
            await websocket.close(code=1011)
        except OSError:
            pass
