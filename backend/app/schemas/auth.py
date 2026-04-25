"""Auth schemas covering WebAuthn and JWT responses."""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

# We deliberately avoid ``pydantic.EmailStr`` here. ``email-validator``
# (its backend) rejects RFC 6762 special-use TLDs such as ``.local`` and
# ``.internal`` — but those are *exactly* the addresses SentinelOps users in
# labs and internal corporate networks need (e.g. ``soc@corp.local``).
# This regex permits any syntactically reasonable address; deliverability is
# a different concern handled outside auth.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _normalize_email(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Email must be a string")
    cleaned = value.strip().lower()
    if not _EMAIL_RE.fullmatch(cleaned) or len(cleaned) > 320:
        raise ValueError("Invalid email address")
    return cleaned


Email = Annotated[str, BeforeValidator(_normalize_email)]


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #


class RegisterBegin(BaseModel):
    email: Email
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
    email: Email


class LoginBeginResponse(BaseModel):
    options: dict[str, Any]
    challenge_id: str


class LoginFinish(BaseModel):
    challenge_id: str
    credential: dict[str, Any]


# --------------------------------------------------------------------------- #
# Password (email + password fallback for envs where WebAuthn is awkward)     #
# --------------------------------------------------------------------------- #


class PasswordRegister(BaseModel):
    email: Email
    password: str = Field(..., min_length=8, max_length=256)
    display_name: str = Field(..., min_length=1, max_length=120)


class PasswordLogin(BaseModel):
    email: Email
    password: str = Field(..., min_length=1, max_length=256)


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
    email: Email
    display_name: str
    created_at: datetime
    is_active: bool
