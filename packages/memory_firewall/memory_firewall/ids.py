"""Identifier and digest helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

__all__ = [
    "constant_time_eq",
    "new_id",
    "new_token",
    "sha256_hex",
    "stable_hmac",
    "token_digest",
]


def new_id(prefix: str) -> str:
    """Opaque, collision-resistant, prefixed identifier (e.g. ``chk_3f2a...``)."""
    return f"{prefix}_{uuid.uuid4().hex}"


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def stable_hmac(key: bytes, data: str | bytes) -> str:
    """HMAC-SHA256 used for the optional tamper-evidence mode.

    The key is supplied from the environment and deliberately lives *outside* the content database
    (``IMPLEMENTATION_BLUEPRINT.md`` §2). With no key configured, Memory Firewall stores a plain
    digest and the docs state that this proves consistency, not safety.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def new_token(nbytes: int = 32) -> str:
    """Cryptographically random bearer token. Returned once; only its digest is persisted."""
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    return sha256_hex(token)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
