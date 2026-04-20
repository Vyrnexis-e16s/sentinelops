"""On-disk encrypted blob storage for Vault objects.

Layout:  ``{VAULT_STORAGE_PATH}/{user_id}/{object_id}.bin``

The on-disk file is the raw ciphertext output from AES-GCM (which already packs
the auth tag onto the end). The nonce + wrapped DEK live in the DB.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from app.core.config import settings


def _user_dir(user_id: uuid.UUID) -> Path:
    p = Path(settings.vault_storage_path) / str(user_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_blob(user_id: uuid.UUID, object_id: uuid.UUID, ciphertext: bytes) -> str:
    path = _user_dir(user_id) / f"{object_id}.bin"
    tmp = path.with_suffix(".bin.tmp")
    tmp.write_bytes(ciphertext)
    os.replace(tmp, path)  # atomic on POSIX
    return str(path)


def read_blob(path: str) -> bytes:
    return Path(path).read_bytes()


def delete_blob(path: str) -> None:
    p = Path(path)
    if p.exists():
        p.unlink()
