"""Server-side identity resolution.

The single most important rule in this codebase (``IMPLEMENTATION_BLUEPRINT.md`` §2): **the client
cannot assert who it is.** Tenant, principal and role are resolved only by looking up
``sha256(bearer token)`` in the ``principals`` table. Request bodies are scanned for identity and
privilege fields; those fields are stripped, recorded as an audit event, and never read.

There is no "trusted header", no "dev bypass" and no ``principal`` query parameter. A missing or
unknown token raises :class:`AuthenticationError`; an insufficient role raises
:class:`AuthorizationError`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .clock import now_iso
from .errors import AuthenticationError, AuthorizationError, ValidationError
from .ids import new_id, new_token, token_digest

__all__ = [
    "FORGEABLE_FIELDS",
    "ROLE_RANK",
    "Principal",
    "create_principal_row",
    "resolve_token",
    "strip_forgeable_fields",
]

ROLE_RANK: dict[str, int] = {"reader": 0, "reviewer": 1, "admin": 2}

#: Fields a caller might try to set that are resolved from protected server state instead.
#: Encountering any of these is logged; they are never honoured.
FORGEABLE_FIELDS: frozenset[str] = frozenset(
    {
        "tenant_id",
        "tenant",
        "principal",
        "principal_id",
        "actor",
        "actor_id",
        "role",
        "trust_tier",
        "trust",
        "authority_tier",
        "approved_by",
        "approved",
        "reviewed_by",
        "signed_by",
        "state",
        "status",
        "is_admin",
        "guard_enforced",
        "token",
    }
)


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    tenant_id: str
    role: str
    status: str = "active"

    @property
    def is_reviewer(self) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK["reviewer"]

    @property
    def is_admin(self) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK["admin"]

    def require(self, role: str) -> None:
        """Raise unless this principal holds at least ``role``."""
        if role not in ROLE_RANK:
            raise ValidationError(f"unknown role: {role}")
        if ROLE_RANK.get(self.role, -1) < ROLE_RANK[role]:
            raise AuthorizationError(
                f"principal '{self.id}' has role '{self.role}' but '{role}' or higher is required"
            )

    def as_dict(self) -> dict[str, Any]:
        return {"principal": self.id, "tenant_id": self.tenant_id, "role": self.role}


#: Used by the engine for internal bootstrap work only (schema seeding). Never reachable from HTTP.
SYSTEM_PRINCIPAL = Principal(id="system", tenant_id="*", role="admin")


def resolve_token(conn: sqlite3.Connection, token: str | None) -> Principal:
    """Resolve a bearer token to a principal, or raise. The only authentication path."""
    if not token or not token.strip():
        raise AuthenticationError("a bearer token is required")
    row = conn.execute(
        "SELECT id, tenant_id, role, status FROM principals WHERE token_sha256 = ?",
        (token_digest(token.strip()),),
    ).fetchone()
    if row is None:
        # Deliberately identical message for 'no such token' and 'disabled' so the endpoint is not
        # an oracle for which tokens exist.
        raise AuthenticationError("invalid or disabled credential")
    if row["status"] != "active":
        raise AuthenticationError("invalid or disabled credential")
    return Principal(id=row["id"], tenant_id=row["tenant_id"], role=row["role"])


def create_principal_row(
    conn: sqlite3.Connection,
    *,
    principal_id: str,
    tenant_id: str,
    role: str,
    token: str | None = None,
) -> tuple[Principal, str]:
    """Insert a principal and return it with its plaintext token (shown once, never stored)."""
    if role not in ROLE_RANK:
        raise ValidationError(f"unknown role: {role}")
    issued = token or new_token()
    conn.execute(
        "INSERT INTO principals(id, tenant_id, role, token_sha256, status, created_at)"
        " VALUES(?,?,?,?, 'active', ?)",
        (principal_id or new_id("prn"), tenant_id, role, token_digest(issued), now_iso()),
    )
    return Principal(id=principal_id, tenant_id=tenant_id, role=role), issued


def strip_forgeable_fields(payload: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """Return ``(clean_payload, ignored_field_names)``.

    Nested objects are walked too, because ``{"document": {"trust_tier": "..."}}`` is the same
    attack as the flat form.
    """
    ignored: list[str] = []

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for k, v in value.items():
                if k in FORGEABLE_FIELDS:
                    ignored.append(k)
                    continue
                out[k] = walk(v)
            return out
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    clean = walk(payload or {})
    return clean, sorted(set(ignored))
