"""Bitemporality: valid time, system time, and the difference between them.

The blueprint is strict about the vocabulary: the word "bitemporal" may only be used if *both*
valid time and recorded (transaction) time are implemented and tested. These tests are what earns
the word.
"""

from __future__ import annotations

import pytest
from tests.conftest import AFTER_V2, BEFORE_V2, POLICY_V2, V2_EFFECTIVE, World

from memory_firewall.clock import now, parse


def _approve_v2(world: World):
    v1 = world.ingest_policy_v1()
    v2 = world.engine.ingest(
        world.admin,
        source_id="policy",
        text=POLICY_V2,
        document_id=v1.document_id,
        effective_from=parse(V2_EFFECTIVE),
    )
    recorded_before_approval = now()
    outcome = world.engine.review(
        world.admin,
        target_type="version",
        target_id=v2.version_id,
        decision="approve",
        reason="Policy owner approved revision 2.",
        effective_from=parse(V2_EFFECTIVE),
    )
    return v1, v2, outcome, recorded_before_approval


@pytest.mark.integration
def test_valid_time_switches_at_the_effective_date(world: World) -> None:
    _approve_v2(world)
    before = world.engine.retrieve(
        world.reader, query="refund period", as_of_valid=parse(BEFORE_V2)
    )
    after = world.engine.retrieve(world.reader, query="refund period", as_of_valid=parse(AFTER_V2))
    assert "30 days" in " ".join(c.text for c in before.context_chunks)
    assert "14 days" in " ".join(c.text for c in after.context_chunks)
    assert "30 days" not in " ".join(c.text for c in after.context_chunks)


@pytest.mark.integration
def test_system_time_answers_what_was_believed_then(world: World) -> None:
    """The property only bitemporality can provide: 'as known at'."""
    _v1, _v2, _outcome, recorded_before = _approve_v2(world)
    as_known_then = world.engine.retrieve(
        world.reader,
        query="refund period",
        as_of_valid=parse(AFTER_V2),
        as_of_recorded=recorded_before,
    )
    as_known_now = world.engine.retrieve(
        world.reader, query="refund period", as_of_valid=parse(AFTER_V2)
    )
    assert "30 days" in " ".join(c.text for c in as_known_then.context_chunks), (
        "at the earlier recorded time the system had not yet learned about revision 2"
    )
    assert "14 days" in " ".join(c.text for c in as_known_now.context_chunks)


@pytest.mark.integration
def test_validity_rows_are_append_only(world: World) -> None:
    v1, _v2, _o, _r = _approve_v2(world)
    with world.engine.db.connect() as conn:
        rows = conn.execute(
            "SELECT state, effective_from, effective_to, system_recorded_from, system_recorded_to"
            " FROM version_validity vv JOIN document_versions dv"
            " ON dv.id = vv.document_version_id WHERE dv.id = ?"
            " ORDER BY vv.system_recorded_from",
            (v1.version_id,),
        ).fetchall()
    assert len(rows) >= 2, "v1 must have its original belief plus the corrected one"
    first, last = rows[0], rows[-1]
    assert first["effective_to"] is None, "the original belief must still say 'open ended'"
    assert first["system_recorded_to"] is not None, (
        "the original belief must be closed in system time"
    )
    assert last["effective_to"] is not None, "the correction must carry the end of the valid period"
    assert last["system_recorded_to"] is None, "the correction must be the currently open row"


@pytest.mark.integration
def test_history_is_queryable_by_an_authorised_reader(world: World) -> None:
    v1, _v2, _o, _r = _approve_v2(world)
    versions = world.engine.document_versions(world.admin, v1.document_id)
    assert len(versions["versions"]) == 2
    assert [v["version"] for v in versions["versions"]] == [1, 2]
    assert all(v["validity"] for v in versions["versions"])


@pytest.mark.integration
def test_a_reader_cannot_read_raw_version_text(world: World) -> None:
    """Raw version text includes quarantined content, so only reviewers get it."""
    v1 = world.ingest_policy_v1()
    as_reader = world.engine.document_versions(world.reader, v1.document_id)
    as_reviewer = world.engine.document_versions(world.admin, v1.document_id)
    assert "raw_text" not in as_reader["versions"][0]
    assert "raw_text" in as_reviewer["versions"][0]


@pytest.mark.integration
def test_new_version_supersedes_without_deleting(world: World) -> None:
    v1 = world.ingest_policy_v1()
    v2 = world.engine.ingest(
        world.admin,
        source_id="policy",
        text="Refunds are allowed within 21 days.",
        document_id=v1.document_id,
    )
    assert v2.version == 2
    with world.engine.db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM document_versions WHERE document_id = ?",
            (v1.document_id,),
        ).fetchone()["n"]
    assert count == 2
    # The superseded version's chunks still exist; the version gate is what hides them.
    with world.engine.db.connect() as conn:
        old_chunks = conn.execute(
            "SELECT COUNT(*) AS n FROM chunks WHERE document_version_id = ?", (v1.version_id,)
        ).fetchone()["n"]
    assert old_chunks >= 1


@pytest.mark.integration
def test_claims_are_superseded_in_valid_time_on_approval(world: World) -> None:
    _approve_v2(world)
    with world.engine.db.connect() as conn:
        rows = conn.execute(
            "SELECT value_number, effective_from, effective_to, system_recorded_to FROM claims"
            " WHERE subject='refund_policy' AND customer_tier='standard' ORDER BY value_number"
        ).fetchall()
    by_value = {r["value_number"]: r for r in rows}
    assert 30.0 in by_value and 14.0 in by_value
    assert by_value[30.0]["effective_to"] is not None, "the 30-day claim must be closed"
    assert by_value[14.0]["effective_to"] is None, "the 14-day claim must be the open one"
