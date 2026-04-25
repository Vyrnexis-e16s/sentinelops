"""Password hashing utilities.

Uses Argon2id (OWASP's recommended password hash) via :mod:`argon2-cffi`.
The hash format is a self-describing PHC string, so parameters can be
adjusted later without a schema migration.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Defaults are sized for ~50ms of work on a modern CPU and 64MiB memory,
# tunable via env in the future. We deliberately do *not* expose them in
# settings yet — changing them mid-deployment would require a rehash on
# verify, which is out of scope here.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain: str) -> str:
    """Return an Argon2id PHC hash of ``plain``."""
    if not plain:
        raise ValueError("password must be non-empty")
    return _HASHER.hash(plain)


def verify_password(plain: str, hashed: str | None) -> bool:
    """Constant-time compare ``plain`` against a stored Argon2id hash.

    Returns ``False`` if the user has no password set or the hash is
    malformed; only ``True`` when the candidate matches.
    """
    if not plain or not hashed:
        return False
    try:
        return _HASHER.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True when ``hashed`` was produced with weaker params than current."""
    try:
        return _HASHER.check_needs_rehash(hashed)
    except InvalidHashError:
        return True
