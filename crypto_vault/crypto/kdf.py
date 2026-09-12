"""Password-based key derivation."""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KEY_SIZE = 32
ARGON2_MEMORY_KIB = 65_536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
PBKDF2_ITERATIONS = 600_000
MAX_PASSWORD_LENGTH = 4096

def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def _validate(password: str, salt: bytes) -> None:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters")
    if len(salt) < SALT_SIZE:
        raise ValueError("Salt must be at least 16 bytes")

def derive_argon2id(password: str, salt: bytes) -> bytes:
    _validate(password, salt)
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError("Argon2id is unavailable; install argon2-cffi") from exc
    return hash_secret_raw(password.encode("utf-8"), salt, ARGON2_TIME_COST,
                           ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, KEY_SIZE, Type.ID)

def derive_pbkdf2(password: str, salt: bytes) -> bytes:
    _validate(password, salt)
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt,
                     iterations=PBKDF2_ITERATIONS).derive(password.encode("utf-8"))

def derive_key(password: str, salt: bytes, algorithm: str = "argon2id") -> bytes:
    if algorithm == "argon2id":
        return derive_argon2id(password, salt)
    if algorithm == "pbkdf2-sha256":
        return derive_pbkdf2(password, salt)
    raise ValueError(f"Unsupported KDF: {algorithm}")
