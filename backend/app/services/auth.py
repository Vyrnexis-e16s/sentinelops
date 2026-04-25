"""WebAuthn registration/login service.

Uses Redis as the challenge store with a 5-minute TTL so that challenges
never leak into the database or survive a restart longer than necessary.
"""
from __future__ import annotations

import base64
import json
import secrets
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.core.errors import AuthError, ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.passwords import hash_password, needs_rehash, verify_password
from app.models.user import User
from app.models.webauthn import WebAuthnCredential

log = get_logger(__name__)

CHALLENGE_TTL_SECONDS = 5 * 60
CHALLENGE_PREFIX = "webauthn:challenge:"


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


async def _store_challenge(
    redis: aioredis.Redis, kind: str, challenge: bytes, context: dict[str, Any]
) -> str:
    challenge_id = secrets.token_urlsafe(24)
    payload = {
        "kind": kind,
        "challenge": _b64url_encode(challenge),
        "context": context,
    }
    await redis.setex(
        CHALLENGE_PREFIX + challenge_id,
        CHALLENGE_TTL_SECONDS,
        json.dumps(payload).encode("utf-8"),
    )
    return challenge_id


async def _pop_challenge(redis: aioredis.Redis, challenge_id: str) -> dict[str, Any]:
    key = CHALLENGE_PREFIX + challenge_id
    raw = await redis.get(key)
    if raw is None:
        raise AuthError("Challenge not found or expired")
    await redis.delete(key)
    data = json.loads(raw)
    return {
        "kind": data["kind"],
        "challenge": _b64url_decode(data["challenge"]),
        "context": data.get("context", {}),
    }


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #


class AuthService:
    def __init__(self, db: AsyncSession, redis: aioredis.Redis) -> None:
        self.db = db
        self.redis = redis

    async def register_begin(self, email: str, display_name: str) -> tuple[uuid.UUID, dict[str, Any], str]:
        existing = await self.db.execute(select(User).where(User.email == email))
        user = existing.scalar_one_or_none()
        if user is None:
            user = User(id=uuid.uuid4(), email=email, display_name=display_name, is_active=True)
            self.db.add(user)
            await self.db.flush()
        elif not user.is_active:
            raise ConflictError("User exists but is inactive")

        cred_rows = await self.db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
        )
        excluded = [
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in cred_rows.scalars().all()
        ]

        options = generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_id=user.id.bytes,
            user_name=user.email,
            user_display_name=user.display_name,
            exclude_credentials=excluded,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        challenge_id = await _store_challenge(
            self.redis, "register", options.challenge, {"user_id": str(user.id)}
        )
        opts_json: dict[str, Any] = json.loads(options_to_json(options))
        await self.db.commit()
        return user.id, opts_json, challenge_id

    async def register_finish(
        self, challenge_id: str, credential: dict[str, Any], nickname: str | None
    ) -> User:
        record = await _pop_challenge(self.redis, challenge_id)
        if record["kind"] != "register":
            raise AuthError("Wrong challenge type")

        user_id = uuid.UUID(record["context"]["user_id"])
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=record["challenge"],
                expected_origin=settings.webauthn_origin,
                expected_rp_id=settings.webauthn_rp_id,
                require_user_verification=False,
            )
        except Exception as exc:
            raise AuthError(f"Registration failed: {exc}") from exc

        cred = WebAuthnCredential(
            id=uuid.uuid4(),
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            user_id=user_id,
            nickname=nickname,
        )
        self.db.add(cred)

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one()
        await self.db.commit()
        await self.db.refresh(user)
        return user

    # ------------------------------------------------------------------ #
    # Login                                                              #
    # ------------------------------------------------------------------ #

    async def login_begin(self, email: str) -> tuple[dict[str, Any], str]:
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if user is None or not user.is_active:
            raise NotFoundError("No such user")

        cred_rows = await self.db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
        )
        allow = [
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in cred_rows.scalars().all()
        ]
        if not allow:
            raise NotFoundError("User has no registered credentials")

        options = generate_authentication_options(
            rp_id=settings.webauthn_rp_id,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        challenge_id = await _store_challenge(
            self.redis, "login", options.challenge, {"user_id": str(user.id)}
        )
        opts_json: dict[str, Any] = json.loads(options_to_json(options))
        return opts_json, challenge_id

    # ------------------------------------------------------------------ #
    # Password (email + password fallback)                                #
    # ------------------------------------------------------------------ #

    async def password_register(self, email: str, password: str, display_name: str) -> User:
        """Create a user with a hashed password, or set the password on an
        existing passkey-only account. Idempotent enough to use as a "first
        time setup" call: if the email already has a password, raises.
        """
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if user is None:
            user = User(
                id=uuid.uuid4(),
                email=email,
                display_name=display_name,
                is_active=True,
                password_hash=hash_password(password),
            )
            self.db.add(user)
            await self.db.flush()
            return user
        if not user.is_active:
            raise ConflictError("User exists but is inactive")
        if user.password_hash:
            raise ConflictError(
                "Email already has a password set; use the sign-in form instead."
            )
        user.password_hash = hash_password(password)
        if display_name and display_name != user.display_name:
            user.display_name = display_name
        await self.db.flush()
        return user

    async def password_login(self, email: str, password: str) -> User:
        """Verify ``email``/``password``; on success, transparently rehash if
        the stored Argon2 parameters have since been strengthened.
        """
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        # Constant-ish work: never short-circuit before touching argon2 so
        # response times don't reveal which of the two checks failed.
        if user is None or not user.is_active or not user.password_hash:
            verify_password(password, None)
            raise AuthError("Invalid email or password")
        if not verify_password(password, user.password_hash):
            raise AuthError("Invalid email or password")
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            await self.db.flush()
        return user

    async def login_finish(self, challenge_id: str, credential: dict[str, Any]) -> User:
        record = await _pop_challenge(self.redis, challenge_id)
        if record["kind"] != "login":
            raise AuthError("Wrong challenge type")

        user_id = uuid.UUID(record["context"]["user_id"])
        raw_id = credential.get("rawId") or credential.get("id")
        if raw_id is None:
            raise AuthError("Credential missing rawId")
        cred_id_bytes = _b64url_decode(raw_id) if isinstance(raw_id, str) else raw_id

        result = await self.db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id_bytes)
        )
        stored = result.scalar_one_or_none()
        if stored is None or stored.user_id != user_id:
            raise AuthError("Unknown credential")

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=record["challenge"],
                expected_origin=settings.webauthn_origin,
                expected_rp_id=settings.webauthn_rp_id,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=False,
            )
        except Exception as exc:
            raise AuthError(f"Authentication failed: {exc}") from exc

        stored.sign_count = verification.new_sign_count
        await self.db.flush()

        user_res = await self.db.execute(select(User).where(User.id == user_id))
        user = user_res.scalar_one()
        await self.db.commit()
        await self.db.refresh(user)
        return user
