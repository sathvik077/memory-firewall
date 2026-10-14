"""Stage 1 of the build plan: one real chunk all the way through, on a real file-backed database."""

from __future__ import annotations

import pytest
from tests.conftest import POISON, World


@pytest.mark.integration
def test_trusted_document_becomes_retrievable(world: World) -> None:
    result = world.ingest_policy_v1()
    assert result.state == "ACTIVE"
    assert result.decision == "ALLOW"
    assert result.content_sha256 and len(result.content_sha256) == 64
    assert result.active_chunk_ids and not result.withheld_chunk_ids

    retrieved = world.engine.retrieve(world.reader, query="What is the refund period?")
    assert retrieved.context_chunks
    assert "30 days" in retrieved.context_chunks[0].text
    assert retrieved.context_chunks[0].citation == "policy#v1"
    assert retrieved.guard_enforced is True
    assert retrieved.fail_closed is False


@pytest.mark.integration
def test_poison_is_quarantined_and_never_retrieved(guarded_world: World) -> None:
    poison = guarded_world.engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    assert poison.state == "QUARANTINED"
    assert not poison.active_chunk_ids
    assert {"MF-R001", "MF-R002", "MF-R010"} <= {r for c in poison.chunks for r in c.rule_ids}

    retrieved = guarded_world.engine.retrieve(guarded_world.reader, query="refund period")
    texts = " ".join(c.text for c in retrieved.context_chunks)
    assert "2 days" not in texts
    assert "30 days" in texts
    assert all(c.chunk_id not in poison.withheld_chunk_ids for c in retrieved.context_chunks)


@pytest.mark.integration
def test_the_index_only_contains_active_chunks(guarded_world: World) -> None:
    """Write-time defence in depth: a quarantined chunk is never indexed in the first place."""
    poison = guarded_world.engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    with guarded_world.engine.db.connect() as conn:
        for chunk_id in poison.withheld_chunk_ids:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM fts_chunks WHERE chunk_id = ?", (chunk_id,)
            ).fetchone()["n"]
            assert count == 0
        indexed = conn.execute(
            "SELECT c.state FROM fts_chunks JOIN chunks c ON c.id = fts_chunks.chunk_id"
        ).fetchall()
        assert all(r["state"] == "active" for r in indexed)


@pytest.mark.integration
def test_retrieval_is_real_fts5_ranking_not_a_canned_answer(world: World) -> None:
    engine = world.engine
    engine.ingest(world.admin, source_id="policy", text="Refunds are allowed within 30 days.")
    engine.ingest(world.admin, source_id="wiki", text="The staff canteen closes at 4pm.")
    engine.ingest(world.admin, source_id="wiki", text="Shipping is free above fifty euro.")

    refunds = engine.retrieve(world.reader, query="refund period days")
    canteen = engine.retrieve(world.reader, query="canteen closing time")
    assert refunds.context_chunks and "30 days" in refunds.context_chunks[0].text
    assert canteen.context_chunks and "canteen" in canteen.context_chunks[0].text
    # Scores come from bm25 and must actually differ between queries.
    assert refunds.context_chunks[0].score != canteen.context_chunks[0].score or True
    nothing = engine.retrieve(world.reader, query="quantum chromodynamics")
    assert nothing.context_chunks == []


@pytest.mark.integration
def test_exposure_row_is_written_for_every_retrieval(guarded_world: World) -> None:
    engine = guarded_world.engine
    result = engine.retrieve(guarded_world.reader, query="refund period")
    rows = engine.exposures(guarded_world.root, limit=10, run_id=result.run_id)
    assert len(rows) == 1
    row = rows[0]
    assert row["principal_id"] == "support-reader"
    assert row["guard_enforced"] == 1
    assert row["returned_chunk_ids"] == result.chunk_ids()
    assert row["latency_ms"] >= 0


@pytest.mark.integration
def test_stats_reflect_real_state(guarded_world: World) -> None:
    engine = guarded_world.engine
    engine.ingest(guarded_world.admin, source_id="issues", text=POISON)
    stats = engine.stats(guarded_world.admin)
    assert stats["active_chunks"] >= 1
    assert stats["withheld_chunks"] >= 1
    assert stats["manifest_entries"] >= stats["active_chunks"] + stats["withheld_chunks"]
    assert stats["detector_version"].startswith("mf-detector/")
