"""Envelope encryption for the Vault module.

Per-user KEK = HKDF(VAULT_MASTER_KEY, info=user_id) via app.core.crypto.
Per-object DEK = random 32 bytes.
Object payload = AES-256-GCM(DEK, plaintext, aad=user_id).
Wrapped DEK   = AES-256-GCM(KEK, DEK).

The DB stores the wrapped DEK and both nonces. The master key never leaves the
server's environment (in production, fetch it from KMS at startup).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core import crypto
from app.core.config import settings


@dataclass(slots=True)
class EncryptedBlob:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    dek_nonce: bytes


def _kek_for(user_id: uuid.UUID) -> bytes:
    return crypto.derive_user_kek(settings.vault_master_key, str(user_id))


def encrypt_for_user(plaintext: bytes, user_id: uuid.UUID) -> EncryptedBlob:
    kek = _kek_for(user_id)
    dek = crypto.generate_dek()

    payload = crypto.aes_gcm_encrypt(dek, plaintext, aad=user_id.bytes)
    wrapped = crypto.wrap_dek(kek, dek)

    return EncryptedBlob(
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        wrapped_dek=wrapped.wrapped,
        dek_nonce=wrapped.wrap_nonce,
    )


def decrypt_for_user(
    *,
    user_id: uuid.UUID,
    ciphertext: bytes,
    nonce: bytes,
    wrapped_dek: bytes,
    dek_nonce: bytes,
) -> bytes:
    kek = _kek_for(user_id)
    dek = crypto.unwrap_dek(kek, wrapped_dek, dek_nonce)
    return crypto.aes_gcm_decrypt(dek, nonce, ciphertext, aad=user_id.bytes)
