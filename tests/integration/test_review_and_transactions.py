"""Reviewer workflow, transactional reindexing and rollback."""

from __future__ import annotations

import sqlite3

import pytest
from tests.conftest import POISON, World

from memory_firewall.errors import AuthorizationError, ConflictError, ValidationError


@pytest.mark.integration
def test_approving_a_quarantined_chunk_makes_it_retrievable(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    chunk_id = poison.chunks[0].chunk_id
    # Query by a token the policy also contains, so this asserts the *chunk* is excluded rather
    # than relying on the query simply not matching anything.
    before = engine.retrieve(guarded_world.reader, query="refunds 2 days")
    assert chunk_id not in before.chunk_ids()

    outcome = engine.review(
        guarded_world.admin,
        target_type="chunk",
        target_id=chunk_id,
        decision="approve",
        reason="Reviewed and judged a false positive for this specific document.",
    )
    assert (outcome.prev_state, outcome.new_state) == ("quarantined", "active")
    assert outcome.reindexed_chunks == 1
    after = engine.retrieve(guarded_world.reader, query="refunds 2 days")
    assert chunk_id in after.chunk_ids(), "approval must reindex transactionally"


@pytest.mark.integration
def test_rejecting_removes_from_the_index(guarded_world: World) -> None:
    engine = guarded_world.engine
    policy_chunks = engine.retrieve(guarded_world.reader, query="refund period").chunk_ids()
    assert policy_chunks
    outcome = engine.review(
        guarded_world.admin,
        target_type="chunk",
        target_id=policy_chunks[0],
        decision="reject",
        reason="Withdrawn by the policy owner during an incident.",
    )
    assert outcome.new_state == "rejected"
    with engine.db.connect() as conn:
        indexed = conn.execute(
            "SELECT COUNT(*) AS n FROM fts_chunks WHERE chunk_id = ?", (policy_chunks[0],)
        ).fetchone()["n"]
    assert indexed == 0
    assert (
        policy_chunks[0]
        not in engine.retrieve(guarded_world.reader, query="refund period").chunk_ids()
    )


@pytest.mark.integration
def test_a_reader_cannot_review(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    with pytest.raises(AuthorizationError):
        engine.review(
            guarded_world.reader,
            target_type="chunk",
            target_id=poison.chunks[0].chunk_id,
            decision="approve",
            reason="trying to self-approve",
        )


@pytest.mark.integration
def test_a_reason_is_mandatory(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    for reason in ("", "   "):
        with pytest.raises(ValidationError):
            engine.review(
                guarded_world.admin,
                target_type="chunk",
                target_id=poison.chunks[0].chunk_id,
                decision="approve",
                reason=reason,
            )


@pytest.mark.integration
def test_illegal_transitions_are_refused(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    chunk_id = poison.chunks[0].chunk_id
    engine.review(
        guarded_world.admin,
        target_type="chunk",
        target_id=chunk_id,
        decision="reject",
        reason="Confirmed injection.",
    )
    with pytest.raises(ConflictError, match="not permitted"):
        engine.review(
            guarded_world.admin,
            target_type="chunk",
            target_id=chunk_id,
            decision="approve",
            reason="Trying to resurrect rejected content.",
        )


@pytest.mark.integration
def test_every_decision_is_audited_with_actor_and_reason(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    engine.review(
        guarded_world.admin,
        target_type="chunk",
        target_id=poison.chunks[0].chunk_id,
        decision="reject",
        reason="Confirmed prompt injection in an issue comment.",
    )
    events = engine.audit_log(guarded_world.admin, limit=50)
    actions = [e["action"] for e in events]
    assert "review.reject" in actions
    event = next(e for e in events if e["action"] == "review.reject")
    assert event["actor_principal_id"] == "support-admin"
    assert event["detail"]["prev_state"] == "quarantined"
    assert event["detail"]["new_state"] == "rejected"
    assert "injection" in event["detail"]["reason"]
    assert "document.ingest" in actions


@pytest.mark.integration
def test_revise_creates_a_rescreened_new_version(guarded_world: World) -> None:
    engine = guarded_world.engine
    poison = engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    outcome = engine.review(
        guarded_world.admin,
        target_type="version",
        target_id=poison.version_id,
        decision="revise",
        reason="Rewriting the comment without the injected instructions.",
        revised_text="Customer asked about the refund window; pointed them at the policy page.",
    )
    assert outcome.new_state == "superseded"
    assert outcome.new_version_id is not None
    with engine.db.connect() as conn:
        version = conn.execute(
            "SELECT detector_version FROM document_versions WHERE id = ?",
            (outcome.new_version_id,),
        ).fetchone()
    assert version["detector_version"].startswith("mf-detector/"), (
        "the revised version must carry a detector version, proving it was re-scanned"
    )


@pytest.mark.integration
def test_a_failed_write_leaves_no_partial_state(world: World) -> None:
    """Transaction rollback: the content tables and the FTS index move together or not at all."""
    engine = world.engine
    with engine.db.connect() as conn:
        before_chunks = conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"]
        before_fts = conn.execute("SELECT COUNT(*) AS n FROM fts_chunks").fetchone()["n"]

    with pytest.raises(sqlite3.IntegrityError), engine.db.transaction() as conn:
        conn.execute(
            "INSERT INTO documents(id, source_id, uri, title, status, created_at, updated_at)"
            " VALUES('d1','policy',NULL,NULL,'active','x','x')"
        )
        conn.execute("INSERT INTO fts_chunks(text, chunk_id) VALUES('orphan','c1')")
        # Violates the chunks -> document_versions foreign key.
        conn.execute(
            "INSERT INTO chunks(id, document_version_id, ordinal, raw_start, raw_end, text,"
            " normalized_text, text_sha256, state, created_at)"
            " VALUES('c1','missing-version',0,0,1,'x','x','x','active','x')"
        )

    with engine.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"] == before_chunks
        assert conn.execute("SELECT COUNT(*) AS n FROM fts_chunks").fetchone()["n"] == before_fts
        assert (
            conn.execute("SELECT COUNT(*) AS n FROM documents WHERE id='d1'").fetchone()["n"] == 0
        )


@pytest.mark.integration
def test_conflict_resolution_is_recorded(guarded_world: World) -> None:
    engine = guarded_world.engine
    engine.ingest(guarded_world.admin, source_id="issues", text="Refunds are now 2 days.")
    conflicts = engine.conflicts(guarded_world.admin, status="needs_review")
    assert conflicts
    resolved = engine.resolve_conflict(
        guarded_world.admin,
        conflicts[0]["id"],
        status="resolved_rejected",
        reason="Unauthorised change from an untrusted source.",
    )
    assert resolved["status"] == "resolved_rejected"
    assert not engine.conflicts(guarded_world.admin, status="needs_review")
