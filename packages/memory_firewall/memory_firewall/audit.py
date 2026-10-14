"""Append-only audit log helpers.

Bounded claim (MF-24): this is an *application-level* audit trail. It records who did what, when,
and the before/after of each state change, and the application never updates or deletes a row. It
is **not** tamper-proof against someone with direct write access to the SQLite file or to the host;
``docs/SECURITY.md`` states that boundary explicitly rather than calling this "immutable".
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .clock import now_iso
from .ids import new_id

__all__ = ["recent", "record"]


def record(
    conn: sqlite3.Connection,
    *,
    action: str,
    actor_principal_id: str | None = None,
    tenant_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
    parent_version_id: str | None = None,
) -> str:
    """Write one audit row inside the caller's transaction."""
    event_id = new_id("aud")
    conn.execute(
        "INSERT INTO audit_events(id, actor_principal_id, tenant_id, action, target_type,"
        " target_id, detail, parent_version_id, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            actor_principal_id,
            tenant_id,
            action,
            target_type,
            target_id,
            json.dumps(detail or {}, sort_keys=True, default=str),
            parent_version_id,
            now_iso(),
        ),
    )
    return event_id


def recent(
    conn: sqlite3.Connection,
    *,
    tenant_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM audit_events"
    params: list[Any] = []
    if tenant_id is not None:
        sql += " WHERE tenant_id = ?"
        params.append(tenant_id)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    params.extend([min(limit, 500), max(0, offset)])
    rows = conn.execute(sql, tuple(params)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        try:
            item["detail"] = json.loads(item.get("detail") or "{}")
        except json.JSONDecodeError:
            item["detail"] = {"_unparsed": item.get("detail")}
        out.append(item)
    return out
