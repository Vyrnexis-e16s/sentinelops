"""/api/v1/auth — WebAuthn register/login + session endpoints."""
from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.redis import get_redis
from app.core.security import create_access_token, current_user
from app.models.user import User
from app.schemas.auth import (
    LoginBegin,
    LoginBeginResponse,
    LoginFinish,
    PasswordLogin,
    PasswordRegister,
    RegisterBegin,
    RegisterBeginResponse,
    RegisterFinish,
    TokenResponse,
    UserOut,
)
from app.schemas.common import StatusResponse
from app.services.audit import AuditService, audit_logger
from app.services.auth import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def _service(
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis)
) -> AuthService:
    return AuthService(db, redis)


@router.post(
    "/webauthn/register/begin",
    response_model=RegisterBeginResponse,
    status_code=status.HTTP_200_OK,
)
async def register_begin(
    payload: RegisterBegin,
    svc: AuthService = Depends(_service),
    audit: AuditService = Depends(audit_logger),
) -> RegisterBeginResponse:
    user_id, options, challenge_id = await svc.register_begin(payload.email, payload.display_name)
    await audit.append(
        actor_id=user_id,
        action="auth.register.begin",
        resource_type="user",
        resource_id=str(user_id),
        metadata={"email": payload.email},
    )
    await svc.db.commit()
    return RegisterBeginResponse(user_id=user_id, options=options, challenge_id=challenge_id)


@router.post("/webauthn/register/finish", response_model=TokenResponse)
async def register_finish(
    payload: RegisterFinish,
    svc: AuthService = Depends(_service),
    audit: AuditService = Depends(audit_logger),
) -> TokenResponse:
    user = await svc.register_finish(payload.challenge_id, payload.credential, payload.nickname)
    await audit.append(
        actor_id=user.id,
        action="auth.register.finish",
        resource_type="user",
        resource_id=str(user.id),
        metadata={"nickname": payload.nickname},
    )
    await svc.db.commit()
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.post("/webauthn/login/begin", response_model=LoginBeginResponse)
async def login_begin(payload: LoginBegin, svc: AuthService = Depends(_service)) -> LoginBeginResponse:
    options, challenge_id = await svc.login_begin(payload.email)
    return LoginBeginResponse(options=options, challenge_id=challenge_id)


@router.post("/webauthn/login/finish", response_model=TokenResponse)
async def login_finish(
    payload: LoginFinish,
    svc: AuthService = Depends(_service),
    audit: AuditService = Depends(audit_logger),
) -> TokenResponse:
    user = await svc.login_finish(payload.challenge_id, payload.credential)
    await audit.append(
        actor_id=user.id,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
    )
    await svc.db.commit()
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.post("/password/register", response_model=TokenResponse)
async def password_register(
    payload: PasswordRegister,
    svc: AuthService = Depends(_service),
    audit: AuditService = Depends(audit_logger),
) -> TokenResponse:
    """Self-service signup with email + password. Returns a JWT immediately
    so the caller is logged in on success.
    """
    user = await svc.password_register(payload.email, payload.password, payload.display_name)
    await audit.append(
        actor_id=user.id,
        action="auth.password.register",
        resource_type="user",
        resource_id=str(user.id),
        metadata={"email": payload.email},
    )
    await svc.db.commit()
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.post("/password/login", response_model=TokenResponse)
async def password_login(
    payload: PasswordLogin,
    svc: AuthService = Depends(_service),
    audit: AuditService = Depends(audit_logger),
) -> TokenResponse:
    user = await svc.password_login(payload.email, payload.password)
    await audit.append(
        actor_id=user.id,
        action="auth.password.login",
        resource_type="user",
        resource_id=str(user.id),
    )
    await svc.db.commit()
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.post("/logout", response_model=StatusResponse)
async def logout(
    user: User = Depends(current_user),
    audit: AuditService = Depends(audit_logger),
    db: AsyncSession = Depends(get_db),
) -> StatusResponse:
    """Logout is stateless (JWT); we simply record an audit event."""
    await audit.append(
        actor_id=user.id,
        action="auth.logout",
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()
    return StatusResponse(status="ok")


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)) -> UserOut:
    return UserOut.model_validate(user)
