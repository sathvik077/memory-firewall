"""MF-11 and the fail-closed property: no cache to go stale, no error that opens the gate."""

from __future__ import annotations

import sqlite3

import pytest
from tests.conftest import World

from memory_firewall.config import FirewallConfig
from memory_firewall.engine import MemoryFirewallEngine
from memory_firewall.identity import Principal
from memory_firewall.integrity import ManifestStore
from memory_firewall.retrieval import guarded_search

pytestmark = pytest.mark.security


def test_revocation_takes_effect_on_the_very_next_call(guarded_world: World) -> None:
    engine = guarded_world.engine
    assert engine.retrieve(guarded_world.reader, query="refund period").context_chunks
    engine.revoke_source(guarded_world.admin, "policy", "incident response")
    assert not engine.retrieve(guarded_world.reader, query="refund period").context_chunks


def test_acl_removal_takes_effect_on_the_very_next_call(guarded_world: World) -> None:
    engine = guarded_world.engine
    assert engine.retrieve(guarded_world.reader, query="refund period").context_chunks
    engine.set_source_acl(guarded_world.root, "policy", ["support-admin"])
    assert not engine.retrieve(guarded_world.reader, query="refund period").context_chunks


def test_repeated_identical_queries_are_not_served_from_a_cache(guarded_world: World) -> None:
    engine = guarded_world.engine
    for _ in range(3):
        assert engine.retrieve(guarded_world.reader, query="refund period").context_chunks
    engine.revoke_source(guarded_world.admin, "policy", "mid-sequence revocation")
    for _ in range(3):
        assert not engine.retrieve(guarded_world.reader, query="refund period").context_chunks


def test_source_expiry_excludes_content(world: World) -> None:
    from memory_firewall.clock import parse

    engine = world.engine
    engine.create_source(
        world.root,
        "temporary",
        trust_tier="reviewed_internal",
        read_acl=["support-reader"],
        expires_at=parse("2026-02-01T00:00:00Z"),
    )
    engine.ingest(
        world.admin,
        source_id="temporary",
        text="Refund pilot programme note.",
        effective_from=parse("2026-01-01T00:00:00Z"),
    )
    # Expiry is a valid-time fact: while the source was still authorised its content was eligible,
    # and today it is not. Recorded time stays at "now" in both queries.
    while_authorised = engine.retrieve(
        world.reader, query="refund pilot", as_of_valid=parse("2026-01-15T00:00:00Z")
    )
    after_expiry = engine.retrieve(world.reader, query="refund pilot")
    assert while_authorised.context_chunks
    assert not after_expiry.context_chunks


def test_the_guard_returns_nothing_when_the_storage_layer_fails(guarded_world: World) -> None:
    """An exception anywhere in the guard must produce an empty, fail-closed result."""

    class ExplodingConnection:
        def execute(self, *args: object, **kwargs: object) -> object:
            raise sqlite3.OperationalError("injected storage failure")

    result = guarded_search(
        ExplodingConnection(),  # type: ignore[arg-type]
        guarded_world.engine.manifests,
        guarded_world.reader,
        query="refund period",
        run_id="test-fail-closed",
    )
    assert result.context_chunks == []
    assert result.candidate_count == 0
    assert result.fail_closed is True
    assert result.guard_enforced is True
    assert result.trace is None
    assert "guard could not prove eligibility" in str(result.fail_reason)


def test_a_failing_manifest_store_fails_closed(guarded_world: World) -> None:
    class ExplodingManifests(ManifestStore):
        def verify(self, key: str, payload: str | bytes) -> bool:
            raise RuntimeError("injected manifest failure")

    broken = ExplodingManifests(guarded_world.engine.config.db_path)
    with guarded_world.engine.db.connect() as conn:
        result = guarded_search(
            conn, broken, guarded_world.reader, query="refund period", run_id="test-manifest-fail"
        )
    assert result.context_chunks == []
    assert result.fail_closed is True


def test_an_empty_or_tokenless_query_returns_nothing_rather_than_everything(
    guarded_world: World,
) -> None:
    engine = guarded_world.engine
    for query in ("!", "   ", "-", "***", "a"):
        result = engine.retrieve(guarded_world.reader, query=query)
        assert result.context_chunks == []
        assert result.guard_enforced is True


def test_a_trust_floor_excludes_weaker_sources(world: World) -> None:
    db = world.engine.config.db_path
    strict = MemoryFirewallEngine(
        db,
        config=FirewallConfig(db_path=db, min_retrieval_trust_tier="authoritative_reviewed"),
    )
    world.ingest_policy_v1()
    world.engine.ingest(world.admin, source_id="wiki", text="Refund escalation wiki page.")

    permissive = world.engine.retrieve(world.reader, query="refund")
    restricted = strict.retrieve(world.reader, query="refund")
    assert {c.source_id for c in permissive.context_chunks} >= {"policy", "wiki"}
    assert {c.source_id for c in restricted.context_chunks} == {"policy"}


def test_a_disabled_principal_cannot_authenticate(guarded_world: World) -> None:
    from memory_firewall.errors import AuthenticationError

    engine = guarded_world.engine
    token = guarded_world.tokens["support-reader"]
    assert engine.authenticate(token).id == "support-reader"
    with engine.db.transaction() as conn:
        conn.execute("UPDATE principals SET status='disabled' WHERE id='support-reader'")
    with pytest.raises(AuthenticationError):
        engine.authenticate(token)


def test_a_principal_from_another_tenant_cannot_be_adopted(guarded_world: World) -> None:
    """Constructing a Principal by hand with someone else's tenant yields no access."""
    engine = guarded_world.engine
    impostor = Principal(id="support-reader", tenant_id="other", role="admin")
    result = engine.retrieve(impostor, query="refund period")
    assert result.context_chunks == [], (
        "the ACL join is on (source, principal) and the tenant predicate is separate, so a "
        "mismatched pair grants nothing"
    )
