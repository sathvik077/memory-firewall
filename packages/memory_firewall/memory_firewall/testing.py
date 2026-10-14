"""Adversarial fixtures — **test-only**.

Everything here deliberately writes to the database with raw SQL, *bypassing the entire pre-write
pipeline*, in order to prove that the pre-retrieval guard is an independent second gate rather than
a cosmetic repetition of the first (``CLAUDE.md`` MF-05, ``TEST_VECTORS.json`` MF-SEED-07 and
MF-SEED-11, blueprint §5).

None of these functions is reachable from the HTTP API, the SDK's public surface or the dashboard.
They are imported only by ``tests/`` and by ``scripts/attack_lab.py``, which runs against a
disposable demo database. If a change ever makes one of them reachable from a request handler,
``tests/security/test_bypass_surface.py`` fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from .clock import iso, now
from .ids import new_id, sha256_hex
from .integrity import ManifestStore

if TYPE_CHECKING:  # pragma: no cover
    from .engine import MemoryFirewallEngine

__all__ = [
    "BYPASS_MODES",
    "InjectedPoison",
    "inject_index_poison",
    "mutate_chunk_text_after_index",
    "orphan_fts_row",
]

BypassMode = Literal[
    "quarantined_chunk_indexed",
    "revoked_source_active_chunk",
    "digest_mismatch",
    "missing_manifest",
    "no_acl_active_chunk",
    "tombstoned_document",
    "expired_version",
    "expired_source",
    "superseded_version",
    "future_recorded_time",
]

#: The ten independent ways poison is forced into the index for the bypass suite. Each one defeats a
#: *different* predicate in the guarded SQL, so a single missing check cannot pass the whole suite.
#: The last three were added after an independent review pointed out that `sources.expires_at`, a
#: non-active `version_validity.state`, and the recorded-time window were enforced by the guard but
#: never independently forced by this helper — so the second-gate proof had a coverage gap even
#: though the predicates held.
BYPASS_MODES: tuple[str, ...] = (
    "quarantined_chunk_indexed",
    "revoked_source_active_chunk",
    "digest_mismatch",
    "missing_manifest",
    "no_acl_active_chunk",
    "tombstoned_document",
    "expired_version",
    "expired_source",
    "superseded_version",
    "future_recorded_time",
)


@dataclass(slots=True)
class InjectedPoison:
    mode: str
    chunk_id: str
    document_id: str
    version_id: str
    source_id: str
    text: str
    indexed: bool
    notes: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "version_id": self.version_id,
            "source_id": self.source_id,
            "text": self.text,
            "indexed": self.indexed,
            "notes": self.notes,
        }


def inject_index_poison(
    engine: MemoryFirewallEngine,
    *,
    source_id: str,
    text: str,
    mode: str = "quarantined_chunk_indexed",
    tenant_id: str | None = None,
    read_acl_principal: str | None = None,
) -> InjectedPoison:
    """Force a poisoned chunk into the live FTS index with the write guard bypassed.

    This is what a bad migration, a direct DB write or a compromised indexer would do. The guard
    must still exclude it, and it must exclude it for the *stated* reason — which is why each mode
    breaks exactly one predicate.
    """
    if mode not in BYPASS_MODES:
        raise ValueError(f"unknown bypass mode '{mode}'; expected one of {BYPASS_MODES}")

    ts = iso(now())
    document_id = new_id("doc")
    version_id = new_id("ver")
    chunk_id = new_id("chk")

    with engine.db.transaction() as conn:
        source = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        if source is None:
            raise ValueError(f"source '{source_id}' does not exist; create it first")
        del tenant_id  # the source's own tenant is authoritative; the argument is advisory

        doc_status = "tombstoned" if mode == "tombstoned_document" else "active"
        conn.execute(
            "INSERT INTO documents(id, source_id, uri, title, status, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (document_id, source_id, "test-only://injected", "injected poison", doc_status, ts, ts),
        )
        conn.execute(
            "INSERT INTO document_versions(id, document_id, version, content_sha256, raw_text,"
            " normalized_text, normalization_report, detector_version, actor_principal_id,"
            " parent_version_id, created_at) VALUES(?,?,1,?,?,?, '{}', 'test-only-bypass', NULL,"
            " NULL, ?)",
            (version_id, document_id, sha256_hex(text), text, text, ts),
        )

        if mode == "superseded_version":
            # Version state is not 'active': the version gate must exclude it.
            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?, 'superseded', '2020-01-01T00:00:00.000000Z',"
                " NULL, '2020-01-01T00:00:00.000000Z', NULL, NULL, 'test-only injection', ?)",
                (new_id("vvl"), version_id, ts),
            )
        elif mode == "future_recorded_time":
            # Recorded-time window opens in the future: the system-time predicate must exclude it
            # for any query asked "as known now".
            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?, 'active', '2020-01-01T00:00:00.000000Z',"
                " NULL, '2099-01-01T00:00:00.000000Z', NULL, NULL, 'test-only injection', ?)",
                (new_id("vvl"), version_id, ts),
            )
        elif mode == "expired_version":
            # A validity interval that ended in the past: valid-time predicate must exclude it.
            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?, 'active', '2020-01-01T00:00:00.000000Z',"
                " '2020-06-01T00:00:00.000000Z', '2020-01-01T00:00:00.000000Z', NULL, NULL,"
                " 'test-only injection', ?)",
                (new_id("vvl"), version_id, ts),
            )
        else:
            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?, 'active', ?, NULL, ?, NULL, NULL,"
                " 'test-only injection', ?)",
                (
                    new_id("vvl"),
                    version_id,
                    "2020-01-01T00:00:00.000000Z",
                    "2020-01-01T00:00:00.000000Z",
                    ts,
                ),
            )

        chunk_state = "quarantined" if mode == "quarantined_chunk_indexed" else "active"
        conn.execute(
            "INSERT INTO chunks(id, document_version_id, ordinal, raw_start, raw_end, text,"
            " normalized_text, text_sha256, state, risk_score, max_severity, created_at)"
            " VALUES(?,?,0,0,?,?,?,?,?,1.0,'critical',?)",
            (chunk_id, version_id, len(text), text, text, sha256_hex(text), chunk_state, ts),
        )

        # The bypass itself: index the chunk regardless of its state.
        conn.execute("INSERT INTO fts_chunks(text, chunk_id) VALUES(?, ?)", (text, chunk_id))

        if mode == "expired_source":
            # Distinct from revocation: the source is still 'active' but its authorisation lapsed.
            conn.execute(
                "UPDATE sources SET expires_at='2020-06-01T00:00:00.000000Z', updated_at=?"
                " WHERE id=?",
                (ts, source_id),
            )
        if mode == "revoked_source_active_chunk":
            conn.execute(
                "UPDATE sources SET status='revoked', revoked_reason='test-only injection',"
                " updated_at=? WHERE id=?",
                (ts, source_id),
            )
        if mode == "no_acl_active_chunk" and read_acl_principal:
            conn.execute(
                "DELETE FROM source_acl WHERE source_id=? AND principal_id=?",
                (source_id, read_acl_principal),
            )

    notes = {
        "quarantined_chunk_indexed": "chunk.state='quarantined' but present in fts_chunks",
        "revoked_source_active_chunk": "active chunk behind a revoked source",
        "digest_mismatch": "manifest digest deliberately does not match the stored text",
        "missing_manifest": "no manifest entry at all; a missing expected value must not pass",
        "no_acl_active_chunk": "active chunk whose source has no read ACL for the caller",
        "tombstoned_document": "active chunk under a tombstoned document",
        "expired_version": "valid-time interval ended in 2020",
        "expired_source": "source still 'active' but its expires_at lapsed in 2020",
        "superseded_version": "version_validity.state is 'superseded', not 'active'",
        "future_recorded_time": "recorded-time window does not open until 2099",
    }[mode]

    # Manifest handling per mode. 'missing_manifest' writes nothing; 'digest_mismatch' writes a
    # digest of different text so the recheck fails.
    key = ManifestStore.chunk_key(chunk_id)
    if mode == "digest_mismatch":
        engine.manifests.put(key, text + "\n<tampered expectation>")
    elif mode != "missing_manifest":
        engine.manifests.put(key, text)

    return InjectedPoison(
        mode=mode,
        chunk_id=chunk_id,
        document_id=document_id,
        version_id=version_id,
        source_id=source_id,
        text=text,
        indexed=True,
        notes=notes,
    )


def mutate_chunk_text_after_index(
    engine: MemoryFirewallEngine, chunk_id: str, new_text: str
) -> dict[str, Any]:
    """Rewrite a chunk's stored text behind the application's back (MF-SEED-11).

    The content DB is changed; the expected digest in the side-store manifest is not. The guard's
    integrity recheck must therefore withhold the chunk and raise an integrity alert.
    """
    with engine.db.transaction() as conn:
        row = conn.execute("SELECT text FROM chunks WHERE id = ?", (chunk_id,)).fetchone()
        if row is None:
            raise ValueError(f"chunk '{chunk_id}' not found")
        before = row["text"]
        conn.execute(
            "UPDATE chunks SET text=?, normalized_text=?, text_sha256=? WHERE id=?",
            (new_text, new_text, sha256_hex(new_text), chunk_id),
        )
        conn.execute("DELETE FROM fts_chunks WHERE chunk_id=?", (chunk_id,))
        conn.execute("INSERT INTO fts_chunks(text, chunk_id) VALUES(?,?)", (new_text, chunk_id))
    return {
        "chunk_id": chunk_id,
        "before": before,
        "after": new_text,
        "manifest_updated": False,
        "expected_digest": engine.manifests.get(ManifestStore.chunk_key(chunk_id)),
    }


def orphan_fts_row(engine: MemoryFirewallEngine, text: str) -> str:
    """Insert an FTS row with no backing chunk at all.

    The guarded query inner-joins ``chunks``, so an orphan row can never surface. This exists to
    prove that claim rather than assume it.
    """
    fake_id = new_id("chk")
    with engine.db.transaction() as conn:
        conn.execute("INSERT INTO fts_chunks(text, chunk_id) VALUES(?,?)", (text, fake_id))
    return fake_id
