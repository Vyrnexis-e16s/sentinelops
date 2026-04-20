"""Vault encryption roundtrip + tamper-rejection tests."""
from __future__ import annotations

import os
import uuid

import pytest

from app.modules.vault.services import encryption


@pytest.fixture(autouse=True)
def _vault_master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_MASTER_KEY", "0" * 64)
    # Force settings reload so the test value sticks.
    from app.core import config as _config

    _config.get_settings.cache_clear()


def test_roundtrip_for_user() -> None:
    user_id = uuid.uuid4()
    plaintext = b"top-secret incident playbook"
    blob = encryption.encrypt_for_user(plaintext, user_id)
    decrypted = encryption.decrypt_for_user(
        user_id=user_id,
        ciphertext=blob.ciphertext,
        nonce=blob.nonce,
        wrapped_dek=blob.wrapped_dek,
        dek_nonce=blob.dek_nonce,
    )
    assert decrypted == plaintext


def test_wrong_user_cannot_decrypt() -> None:
    owner = uuid.uuid4()
    other = uuid.uuid4()
    blob = encryption.encrypt_for_user(b"hello", owner)
    with pytest.raises(Exception):
        encryption.decrypt_for_user(
            user_id=other,
            ciphertext=blob.ciphertext,
            nonce=blob.nonce,
            wrapped_dek=blob.wrapped_dek,
            dek_nonce=blob.dek_nonce,
        )


def test_tamper_breaks_decrypt() -> None:
    user_id = uuid.uuid4()
    blob = encryption.encrypt_for_user(b"hello world", user_id)
    tampered = bytearray(blob.ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(Exception):
        encryption.decrypt_for_user(
            user_id=user_id,
            ciphertext=bytes(tampered),
            nonce=blob.nonce,
            wrapped_dek=blob.wrapped_dek,
            dek_nonce=blob.dek_nonce,
        )


def test_large_payload_roundtrip() -> None:
    user_id = uuid.uuid4()
    payload = os.urandom(1024 * 256)  # 256 KiB
    blob = encryption.encrypt_for_user(payload, user_id)
    decrypted = encryption.decrypt_for_user(
        user_id=user_id,
        ciphertext=blob.ciphertext,
        nonce=blob.nonce,
        wrapped_dek=blob.wrapped_dek,
        dek_nonce=blob.dek_nonce,
    )
    assert decrypted == payload
