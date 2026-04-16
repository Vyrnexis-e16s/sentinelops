"""Auth schemas covering WebAuthn and JWT responses."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #


class RegisterBegin(BaseModel):
    email: EmailStr
    display_name: str = Field(..., min_length=1, max_length=120)


class RegisterBeginResponse(BaseModel):
    user_id: uuid.UUID
    options: dict[str, Any]
    challenge_id: str


class RegisterFinish(BaseModel):
    challenge_id: str
    credential: dict[str, Any]
    nickname: str | None = Field(default=None, max_length=120)


# --------------------------------------------------------------------------- #
# Login                                                                       #
# --------------------------------------------------------------------------- #


class LoginBegin(BaseModel):
    email: EmailStr


class LoginBeginResponse(BaseModel):
    options: dict[str, Any]
    challenge_id: str


class LoginFinish(BaseModel):
    challenge_id: str
    credential: dict[str, Any]


# --------------------------------------------------------------------------- #
# Token / user                                                                #
# --------------------------------------------------------------------------- #


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    display_name: str
    created_at: datetime
    is_active: bool
