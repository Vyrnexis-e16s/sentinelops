"""Cryptographic primitives: AES-256-GCM, HKDF, HMAC audit chain."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_BYTES = 32   # AES-256
GCM_NONCE_BYTES = 12
ZERO_HASH = b"\x00" * 32


# --------------------------------------------------------------------------- #
# Master-key loading                                                          #
# --------------------------------------------------------------------------- #


def _decode_master_key(raw: str) -> bytes:
    """Accept hex, base64-urlsafe, or raw bytes for the vault master key."""
    try:
        val = bytes.fromhex(raw)
        if len(val) >= AES_KEY_BYTES:
            return val[:AES_KEY_BYTES]
    except ValueError:
        pass
    # Fallback: derive 32 bytes from the provided string via SHA-256.
    return hashlib.sha256(raw.encode("utf-8")).digest()


# --------------------------------------------------------------------------- #
# HKDF                                                                        #
# --------------------------------------------------------------------------- #


def hkdf(
    ikm: bytes,
    *,
    info: bytes,
    salt: bytes | None = None,
    length: int = AES_KEY_BYTES,
) -> bytes:
    """HKDF-SHA256."""
    h = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return h.derive(ikm)


def derive_user_kek(master_key: str, user_id: str) -> bytes:
    """Derive a per-user Key Encryption Key from the master key."""
    ikm = _decode_master_key(master_key)
    return hkdf(ikm, info=f"sentinelops:vault:kek:{user_id}".encode(), length=AES_KEY_BYTES)


# --------------------------------------------------------------------------- #
# AES-256-GCM                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class AeadResult:
    ciphertext: bytes
    nonce: bytes


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> AeadResult:
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_BYTES} bytes, got {len(key)}")
    nonce = os.urandom(GCM_NONCE_BYTES)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return AeadResult(ciphertext=ct, nonce=nonce)


def aes_gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None
) -> bytes:
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_BYTES} bytes, got {len(key)}")
    aead = AESGCM(key)
    return aead.decrypt(nonce, ciphertext, aad)


# --------------------------------------------------------------------------- #
# DEK / KEK wrapping                                                          #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class WrappedDEK:
    wrapped: bytes
    wrap_nonce: bytes


def generate_dek() -> bytes:
    return os.urandom(AES_KEY_BYTES)


def wrap_dek(kek: bytes, dek: bytes) -> WrappedDEK:
    result = aes_gcm_encrypt(kek, dek)
    return WrappedDEK(wrapped=result.ciphertext, wrap_nonce=result.nonce)


def unwrap_dek(kek: bytes, wrapped: bytes, wrap_nonce: bytes) -> bytes:
    return aes_gcm_decrypt(kek, wrap_nonce, wrapped)


# --------------------------------------------------------------------------- #
# Audit HMAC / hash chain                                                     #
# --------------------------------------------------------------------------- #


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding for hash chain / signature computations."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def audit_entry_hash(prev_hash: bytes, entry: dict[str, Any]) -> bytes:
    """entry_hash = SHA-256(prev_hash || canonical_json(entry))."""
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(canonical_json(entry))
    return h.digest()


def audit_hmac(secret: bytes, entry_hash: bytes) -> bytes:
    """Optional HMAC of the entry hash so a leaked DB can't silently rewrite history."""
    return hmac.new(secret, entry_hash, hashlib.sha256).digest()


def verify_audit_chain(entries: list[dict[str, Any]]) -> bool:
    """Verify an ordered list of audit entries. Each entry must have
    ``prev_hash``, ``entry_hash`` (bytes) and the raw hashable payload under ``payload``.
    """
    prev = ZERO_HASH
    for e in entries:
        if e.get("prev_hash") != prev:
            return False
        expected = audit_entry_hash(prev, e["payload"])
        if expected != e.get("entry_hash"):
            return False
        prev = expected
    return True
