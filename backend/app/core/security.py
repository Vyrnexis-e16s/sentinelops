"""JWT helpers and the ``current_user`` FastAPI dependency."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, Header
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.errors import AuthError
from app.models.user import User


def create_access_token(
    subject: str | uuid.UUID,
    *,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a signed JWT carrying ``sub`` = user id."""
    now = datetime.now(tz=timezone.utc)
    exp = now + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": settings.app_name,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub"]},
            issuer=settings.app_name,
        )
    except InvalidTokenError as exc:
        raise AuthError(f"Invalid token: {exc}") from exc


def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        raise AuthError("Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError("Expected 'Bearer <token>' Authorization header")
    return token


async def current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate the JWT and resolve the ``User`` record, or 401."""
    token = _extract_bearer(authorization)
    payload = decode_access_token(token)
    subject = payload.get("sub")
    if not subject:
        raise AuthError("Token missing subject")
    try:
        user_id = uuid.UUID(str(subject))
    except ValueError as exc:
        raise AuthError("Subject is not a valid UUID") from exc

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive")
    return user


async def optional_current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Same as :func:`current_user` but returns None when absent."""
    if not authorization:
        return None
    try:
        return await current_user(authorization=authorization, db=db)
    except AuthError:
        return None
