"""Identity resolution, privileged-field stripping and bitemporal time helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from memory_firewall.clock import fixed_clock, iso, now, parse
from memory_firewall.db import Database
from memory_firewall.errors import AuthenticationError, AuthorizationError
from memory_firewall.identity import (
    FORGEABLE_FIELDS,
    Principal,
    create_principal_row,
    resolve_token,
    strip_forgeable_fields,
)


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    db = Database(tmp_path / "x.sqlite3")
    db.migrate()
    with db.transaction() as c:
        c.execute("INSERT INTO tenants(id, name, created_at) VALUES('t','T',?)", (iso(now()),))
        create_principal_row(
            c, principal_id="reader", tenant_id="t", role="reader", token="reader-token"
        )
    stack = db.connect()
    connection = stack.__enter__()
    yield connection
    stack.__exit__(None, None, None)


def test_token_resolves_to_the_server_side_principal(conn: sqlite3.Connection) -> None:
    principal = resolve_token(conn, "reader-token")
    assert principal.id == "reader"
    assert principal.tenant_id == "t"
    assert principal.role == "reader"


def test_plaintext_token_is_never_stored(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT token_sha256 FROM principals WHERE id='reader'").fetchone()
    assert row["token_sha256"] != "reader-token"
    assert len(row["token_sha256"]) == 64


@pytest.mark.parametrize("token", [None, "", "   ", "wrong-token", "reader-token "])
def test_bad_tokens_raise_except_for_surrounding_whitespace(
    conn: sqlite3.Connection, token: str | None
) -> None:
    if token == "reader-token ":
        assert resolve_token(conn, token).id == "reader"
        return
    with pytest.raises(AuthenticationError):
        resolve_token(conn, token)


def test_unknown_and_disabled_tokens_are_indistinguishable(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE principals SET status='disabled' WHERE id='reader'")
    with pytest.raises(AuthenticationError) as disabled:
        resolve_token(conn, "reader-token")
    with pytest.raises(AuthenticationError) as unknown:
        resolve_token(conn, "no-such-token")
    assert str(disabled.value) == str(unknown.value)


def test_role_hierarchy() -> None:
    reader = Principal(id="r", tenant_id="t", role="reader")
    reviewer = Principal(id="v", tenant_id="t", role="reviewer")
    admin = Principal(id="a", tenant_id="t", role="admin")
    assert not reader.is_reviewer and not reader.is_admin
    assert reviewer.is_reviewer and not reviewer.is_admin
    assert admin.is_reviewer and admin.is_admin
    with pytest.raises(AuthorizationError):
        reader.require("reviewer")
    with pytest.raises(AuthorizationError):
        reviewer.require("admin")
    admin.require("admin")


def test_forgeable_fields_are_stripped_including_nested() -> None:
    clean, ignored = strip_forgeable_fields(
        {
            "text": "hello",
            "tenant_id": "support",
            "principal": "support-admin",
            "document": {"trust_tier": "authoritative_signed", "title": "t"},
            "list": [{"approved_by": "admin", "keep": 1}],
        }
    )
    assert clean == {"text": "hello", "document": {"title": "t"}, "list": [{"keep": 1}]}
    assert set(ignored) == {"tenant_id", "principal", "trust_tier", "approved_by"}


def test_the_forgeable_set_covers_every_authority_concept() -> None:
    for field in ("tenant_id", "principal", "role", "trust_tier", "approved_by", "state", "token"):
        assert field in FORGEABLE_FIELDS


def test_empty_payload_is_handled() -> None:
    assert strip_forgeable_fields(None) == ({}, [])
    assert strip_forgeable_fields({}) == ({}, [])


def test_iso_strings_sort_chronologically() -> None:
    earlier = iso(parse("2026-01-01T00:00:00Z"))
    later = iso(parse("2026-12-01T00:00:00Z"))
    assert earlier < later  # SQLite string comparison must be a correct time comparison


def test_fixed_clock_is_deterministic_and_restores() -> None:
    before = now()
    with fixed_clock("2026-10-14T09:00:00Z") as frozen:
        assert now() == frozen
        assert now() == frozen
    assert now() >= before


def test_naive_datetimes_are_treated_as_utc() -> None:
    assert parse("2026-10-14T09:00:00").tzinfo is not None
    assert parse("2026-10-14T09:00:00") == parse("2026-10-14T09:00:00Z")
