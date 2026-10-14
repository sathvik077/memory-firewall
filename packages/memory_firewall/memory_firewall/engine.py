"""``MemoryFirewallEngine`` — the single policy authority.

Both the HTTP API and the Python SDK are thin shells over this class. There is exactly one
implementation of every security decision, so the API and the SDK cannot drift apart and a reviewer
transition behaves identically however it was triggered (``IMPLEMENTATION_BLUEPRINT.md`` §4.4).

Transaction discipline: one ingest, one review decision or one revocation is one
``BEGIN IMMEDIATE`` block covering the content tables *and* the FTS index, so the index can never
describe a state the tables do not have. Manifests live in a different file and are written after
the content transaction commits; a manifest that is missing or stale makes the affected chunk
*unretrievable* rather than trusted, so that ordering fails safe.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from . import audit
from ._version import DETECTOR_VERSION, POLICY_REVISION
from .chunking import chunk_normalized
from .claims import Claim, ClaimConflict, compare_claims, extract_claims
from .clock import iso, now, parse, to_utc
from .config import TRUST_ORDER, FirewallConfig
from .contextpack import ContextPack, build_context_pack
from .db import Database
from .detector import ScanReport, scan
from .errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    PolicyError,
    ValidationError,
)
from .identity import Principal, create_principal_row, resolve_token
from .ids import new_id
from .integrity import ManifestStore
from .normalize import normalize_text
from .policy import DECISION_STATE, TRANSITIONS, PolicyOutcome, decide_write
from .preview import highlight_spans, truncate_preview
from .retrieval import RetrievalResult, guarded_search, unguarded_search_for_baseline

__all__ = ["ChunkOutcome", "IngestResult", "MemoryFirewallEngine", "ReviewOutcome"]

VALID_TRUST_TIERS = tuple(TRUST_ORDER)


@dataclass(slots=True)
class ChunkOutcome:
    chunk_id: str
    ordinal: int
    decision: str
    state: str
    reasons: list[str]
    risk_score: float
    max_severity: str
    rule_ids: list[str]
    raw_span: tuple[int, int]
    preview: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "ordinal": self.ordinal,
            "decision": self.decision,
            "state": self.state,
            "reasons": self.reasons,
            "risk_score": self.risk_score,
            "max_severity": self.max_severity,
            "rule_ids": self.rule_ids,
            "raw_span": list(self.raw_span),
            "preview": self.preview,
        }


@dataclass(slots=True)
class IngestResult:
    document_id: str
    version_id: str
    version: int
    source_id: str
    content_sha256: str
    #: Document-level roll-up: ``ACTIVE``, ``QUARANTINED``, ``REJECTED``, ``REVIEW_REQUIRED`` or
    #: ``PARTIALLY_WITHHELD`` when some chunks are active and others are not.
    state: str = "ACTIVE"
    decision: str = "ALLOW"
    chunks: list[ChunkOutcome] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    normalization_report: dict[str, Any] = field(default_factory=dict)
    ignored_privileged_fields: list[str] = field(default_factory=list)
    effective_from: str = ""
    detector_version: str = DETECTOR_VERSION
    policy_revision: str = POLICY_REVISION

    @property
    def active_chunk_ids(self) -> list[str]:
        return [c.chunk_id for c in self.chunks if c.state == "active"]

    @property
    def withheld_chunk_ids(self) -> list[str]:
        return [c.chunk_id for c in self.chunks if c.state != "active"]

    def as_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "version_id": self.version_id,
            "version": self.version,
            "source_id": self.source_id,
            "content_sha256": self.content_sha256,
            "state": self.state,
            "decision": self.decision,
            "chunks": [c.as_dict() for c in self.chunks],
            "findings": self.findings,
            "claims": self.claims,
            "conflicts": self.conflicts,
            "normalization_report": self.normalization_report,
            "ignored_privileged_fields": self.ignored_privileged_fields,
            "effective_from": self.effective_from,
            "detector_version": self.detector_version,
            "policy_revision": self.policy_revision,
            "active_chunk_ids": self.active_chunk_ids,
            "withheld_chunk_ids": self.withheld_chunk_ids,
            "identity_source": "verified_token",
        }


@dataclass(slots=True)
class ReviewOutcome:
    target_type: str
    target_id: str
    decision: str
    prev_state: str
    new_state: str
    reviewer: str
    reason: str
    review_id: str
    reindexed_chunks: int = 0
    superseded_versions: list[str] = field(default_factory=list)
    new_version_id: str | None = None
    effective_from: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "decision": self.decision,
            "prev_state": self.prev_state,
            "new_state": self.new_state,
            "reviewer": self.reviewer,
            "reason": self.reason,
            "review_id": self.review_id,
            "reindexed_chunks": self.reindexed_chunks,
            "superseded_versions": self.superseded_versions,
            "new_version_id": self.new_version_id,
            "effective_from": self.effective_from,
            "identity_source": "verified_token",
        }


class MemoryFirewallEngine:
    """Everything the firewall can do, with authority checked on every call."""

    def __init__(self, db_path: str | Path, *, config: FirewallConfig | None = None) -> None:
        self.config = config or FirewallConfig()
        self.config.db_path = Path(db_path) if str(db_path) != ":memory:" else Path(":memory:")
        self.db = Database(self.config.db_path)
        self.manifests = ManifestStore(self.config.db_path, hmac_key=self.config.hmac_key)
        self.db.migrate()

    # ------------------------------------------------------------------ identity --------------
    def authenticate(self, token: str | None) -> Principal:
        with self.db.connect() as conn:
            return resolve_token(conn, token)

    # ------------------------------------------------------------------ administration --------
    @staticmethod
    def _actor_fk(conn: sqlite3.Connection, actor_id: str | None) -> str | None:
        """Return ``actor_id`` only when it exists in ``principals``.

        Bootstrap and SDK calls legitimately run as an operator identity that predates any
        principal row. Storing ``NULL`` there keeps the foreign key honest instead of inventing a
        principal, and the audit trail still records the actor string.
        """
        if not actor_id:
            return None
        row = conn.execute("SELECT 1 FROM principals WHERE id = ?", (actor_id,)).fetchone()
        return actor_id if row else None

    def bootstrap(
        self,
        *,
        tenant_id: str,
        admin_id: str = "root-admin",
        token: str | None = None,
        tenant_name: str = "",
    ) -> tuple[Principal, str]:
        """Create a tenant and its first admin principal in one transaction.

        This is the only way an admin comes into existence, and it requires filesystem access to
        the database — there is no HTTP route to it. ``make setup`` calls it once and writes the
        issued tokens to a gitignored ``.env``.
        """
        ts = iso(now())
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO tenants(id, name, created_at) VALUES(?,?,?)"
                " ON CONFLICT(id) DO NOTHING",
                (tenant_id, tenant_name or tenant_id, ts),
            )
            existing = conn.execute(
                "SELECT id, tenant_id, role FROM principals WHERE id = ?", (admin_id,)
            ).fetchone()
            if existing is not None:
                raise ConflictError(
                    f"principal '{admin_id}' already exists; its token cannot be re-issued"
                )
            principal, issued = create_principal_row(
                conn, principal_id=admin_id, tenant_id=tenant_id, role="admin", token=token
            )
            audit.record(
                conn,
                action="bootstrap.admin",
                actor_principal_id=admin_id,
                tenant_id=tenant_id,
                target_type="principal",
                target_id=admin_id,
                detail={"role": "admin"},
            )
        return principal, issued

    def create_tenant(self, actor: Principal, tenant_id: str, name: str = "") -> dict[str, Any]:
        actor.require("admin")
        if not tenant_id or not tenant_id.replace("-", "").replace("_", "").isalnum():
            raise ValidationError("tenant_id must be alphanumeric with - or _")
        with self.db.transaction() as conn:
            existing = conn.execute("SELECT id FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
            if existing:
                raise ConflictError(f"tenant '{tenant_id}' already exists")
            conn.execute(
                "INSERT INTO tenants(id, name, created_at) VALUES(?,?,?)",
                (tenant_id, name or tenant_id, iso(now())),
            )
            audit.record(
                conn,
                action="tenant.create",
                actor_principal_id=actor.id,
                tenant_id=tenant_id,
                target_type="tenant",
                target_id=tenant_id,
            )
        return {"tenant_id": tenant_id, "name": name or tenant_id}

    def create_principal(
        self,
        actor: Principal,
        principal_id: str,
        tenant_id: str,
        role: str,
        token: str | None = None,
    ) -> tuple[Principal, str]:
        actor.require("admin")
        with self.db.transaction() as conn:
            if not conn.execute("SELECT 1 FROM tenants WHERE id = ?", (tenant_id,)).fetchone():
                raise NotFoundError(f"unknown tenant '{tenant_id}'")
            if conn.execute("SELECT 1 FROM principals WHERE id = ?", (principal_id,)).fetchone():
                raise ConflictError(f"principal '{principal_id}' already exists")
            principal, issued = create_principal_row(
                conn, principal_id=principal_id, tenant_id=tenant_id, role=role, token=token
            )
            audit.record(
                conn,
                action="principal.create",
                actor_principal_id=actor.id,
                tenant_id=tenant_id,
                target_type="principal",
                target_id=principal_id,
                detail={"role": role},
            )
        return principal, issued

    def create_source(
        self,
        actor: Principal,
        source_id: str,
        *,
        trust_tier: str,
        read_acl: Sequence[str] = (),
        tenant_id: str | None = None,
        connector_type: str = "manual",
        owner: str | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Create a source. ``trust_tier`` is administrative state set here and nowhere else."""
        actor.require("admin")
        if trust_tier not in TRUST_ORDER:
            raise ValidationError(f"unknown trust_tier '{trust_tier}'")
        tenant = tenant_id or actor.tenant_id
        if tenant != actor.tenant_id and actor.tenant_id != "*":
            raise AuthorizationError("cannot create a source in another tenant")
        ts = iso(now())
        with self.db.transaction() as conn:
            if not conn.execute("SELECT 1 FROM tenants WHERE id = ?", (tenant,)).fetchone():
                raise NotFoundError(f"unknown tenant '{tenant}'")
            if conn.execute("SELECT 1 FROM sources WHERE id = ?", (source_id,)).fetchone():
                raise ConflictError(f"source '{source_id}' already exists")
            conn.execute(
                "INSERT INTO sources(id, tenant_id, connector_type, owner, trust_tier, status,"
                " expires_at, created_at, updated_at, set_by) VALUES(?,?,?,?,?, 'active', ?,?,?,?)",
                (
                    source_id,
                    tenant,
                    connector_type,
                    owner or actor.id,
                    trust_tier,
                    iso(to_utc(expires_at)) if expires_at else None,
                    ts,
                    ts,
                    self._actor_fk(conn, actor.id),
                ),
            )
            for principal_id in read_acl:
                row = conn.execute(
                    "SELECT tenant_id FROM principals WHERE id = ?", (principal_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"unknown principal '{principal_id}'")
                if row["tenant_id"] != tenant:
                    raise AuthorizationError(
                        f"principal '{principal_id}' belongs to a different tenant and cannot be "
                        "granted read access"
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO source_acl(source_id, principal_id, permission,"
                    " granted_at, granted_by) VALUES(?,?, 'read', ?,?)",
                    (source_id, principal_id, ts, self._actor_fk(conn, actor.id)),
                )
            audit.record(
                conn,
                action="source.create",
                actor_principal_id=actor.id,
                tenant_id=tenant,
                target_type="source",
                target_id=source_id,
                detail={"trust_tier": trust_tier, "read_acl": list(read_acl)},
            )
        return {
            "source_id": source_id,
            "tenant_id": tenant,
            "trust_tier": trust_tier,
            "status": "active",
            "read_acl": list(read_acl),
        }

    def set_source_acl(
        self, actor: Principal, source_id: str, read_acl: Sequence[str]
    ) -> dict[str, Any]:
        """Replace a source's read ACL. Takes effect immediately — there is no cache to invalidate."""
        actor.require("admin")
        ts = iso(now())
        with self.db.transaction() as conn:
            source = self._require_source(conn, source_id, actor)
            previous = [
                r["principal_id"]
                for r in conn.execute(
                    "SELECT principal_id FROM source_acl WHERE source_id = ? AND permission='read'",
                    (source_id,),
                ).fetchall()
            ]
            conn.execute(
                "DELETE FROM source_acl WHERE source_id = ? AND permission = 'read'", (source_id,)
            )
            for principal_id in read_acl:
                row = conn.execute(
                    "SELECT tenant_id FROM principals WHERE id = ?", (principal_id,)
                ).fetchone()
                if row is None or row["tenant_id"] != source["tenant_id"]:
                    raise AuthorizationError(
                        f"principal '{principal_id}' cannot be granted read access to this source"
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO source_acl(source_id, principal_id, permission,"
                    " granted_at, granted_by) VALUES(?,?, 'read', ?,?)",
                    (source_id, principal_id, ts, self._actor_fk(conn, actor.id)),
                )
            audit.record(
                conn,
                action="source.acl.replace",
                actor_principal_id=actor.id,
                tenant_id=source["tenant_id"],
                target_type="source",
                target_id=source_id,
                detail={"before": previous, "after": list(read_acl)},
            )
        return {"source_id": source_id, "read_acl": list(read_acl)}

    def revoke_source(self, actor: Principal, source_id: str, reason: str = "") -> dict[str, Any]:
        """Revoke a source. Every chunk behind it stops being retrievable on the next query."""
        actor.require("reviewer")
        with self.db.transaction() as conn:
            source = self._require_source(conn, source_id, actor)
            conn.execute(
                "UPDATE sources SET status='revoked', revoked_reason=?, updated_at=? WHERE id=?",
                (reason or "revoked by reviewer", iso(now()), source_id),
            )
            audit.record(
                conn,
                action="source.revoke",
                actor_principal_id=actor.id,
                tenant_id=source["tenant_id"],
                target_type="source",
                target_id=source_id,
                detail={"reason": reason},
            )
        return {"source_id": source_id, "status": "revoked", "reason": reason}

    def tombstone_document(
        self, actor: Principal, document_id: str, reason: str = "", *, purge: bool = False
    ) -> dict[str, Any]:
        """Tombstone (or fully purge) a document.

        ``purge=True`` implements the retention-removal requirement in ``CLAUDE.md`` §3: content
        rows, FTS rows and manifests are deleted. Audit rows are kept, because deleting the record
        that a deletion happened would make the audit trail useless.
        """
        actor.require("reviewer")
        chunk_ids: list[str] = []
        with self.db.transaction() as conn:
            doc = conn.execute(
                "SELECT d.id, d.source_id, s.tenant_id FROM documents d JOIN sources s"
                " ON s.id = d.source_id WHERE d.id = ?",
                (document_id,),
            ).fetchone()
            if doc is None or doc["tenant_id"] != actor.tenant_id:
                raise NotFoundError("document not found")
            chunk_ids = [
                r["id"]
                for r in conn.execute(
                    "SELECT c.id FROM chunks c JOIN document_versions dv"
                    " ON dv.id = c.document_version_id WHERE dv.document_id = ?",
                    (document_id,),
                ).fetchall()
            ]
            if purge:
                self._unindex(conn, chunk_ids)
                conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))
            else:
                conn.execute(
                    "UPDATE documents SET status='tombstoned', updated_at=? WHERE id=?",
                    (iso(now()), document_id),
                )
            audit.record(
                conn,
                action="document.purge" if purge else "document.tombstone",
                actor_principal_id=actor.id,
                tenant_id=doc["tenant_id"],
                target_type="document",
                target_id=document_id,
                detail={"reason": reason, "chunks": len(chunk_ids)},
            )
        if purge:
            for cid in chunk_ids:
                self.manifests.delete(ManifestStore.chunk_key(cid))
        return {
            "document_id": document_id,
            "status": "purged" if purge else "tombstoned",
            "chunks_affected": len(chunk_ids),
        }

    # ------------------------------------------------------------------ ingestion -------------
    def ingest(
        self,
        actor: Principal,
        *,
        source_id: str,
        text: str,
        uri: str | None = None,
        title: str | None = None,
        effective_from: datetime | None = None,
        document_id: str | None = None,
        ignored_privileged_fields: Sequence[str] = (),
    ) -> IngestResult:
        """Enforcement point #1. Hash, normalise, scan, extract claims, decide, persist in one txn."""
        actor.require("reviewer")
        if not isinstance(text, str) or not text.strip():
            raise ValidationError("document content must be a non-empty string")
        size = len(text.encode("utf-8"))
        if size > self.config.max_document_bytes:
            raise ValidationError(
                f"document is {size} bytes which exceeds the {self.config.max_document_bytes}-byte limit"
            )

        norm = normalize_text(text)
        content_digest = __import__("hashlib").sha256(text.encode("utf-8")).hexdigest()
        spans = chunk_normalized(norm, max_chars=self.config.max_chunk_chars)
        if not spans:
            raise ValidationError("document contained no indexable text after normalisation")

        eff = iso(to_utc(effective_from)) if effective_from else iso(now())
        ts = iso(now())

        with self.db.transaction() as conn:
            source = self._require_source(conn, source_id, actor, require_active=True)
            trust_tier = source["trust_tier"]

            existing_claims = self._active_claims(conn, actor.tenant_id)

            # document + version
            if document_id:
                doc = conn.execute(
                    "SELECT d.*, s.tenant_id FROM documents d JOIN sources s ON s.id = d.source_id"
                    " WHERE d.id = ?",
                    (document_id,),
                ).fetchone()
                if doc is None or doc["tenant_id"] != actor.tenant_id:
                    raise NotFoundError("document not found")
                if doc["source_id"] != source_id:
                    raise ValidationError("document belongs to a different source")
                if doc["status"] != "active":
                    raise ConflictError("document is tombstoned and cannot take a new version")
                doc_id = document_id
                row = conn.execute(
                    "SELECT MAX(version) AS v FROM document_versions WHERE document_id = ?",
                    (doc_id,),
                ).fetchone()
                version_number = int(row["v"] or 0) + 1
                parent = conn.execute(
                    "SELECT id FROM document_versions WHERE document_id = ? ORDER BY version DESC"
                    " LIMIT 1",
                    (doc_id,),
                ).fetchone()
                parent_version_id = parent["id"] if parent else None
                conn.execute(
                    "UPDATE documents SET updated_at=?, title=COALESCE(?, title),"
                    " uri=COALESCE(?, uri) WHERE id=?",
                    (ts, title, uri, doc_id),
                )
            else:
                doc_id = new_id("doc")
                version_number = 1
                parent_version_id = None
                conn.execute(
                    "INSERT INTO documents(id, source_id, uri, title, status, created_at,"
                    " updated_at) VALUES(?,?,?,?, 'active', ?,?)",
                    (doc_id, source_id, uri, title, ts, ts),
                )

            version_id = new_id("ver")
            conn.execute(
                "INSERT INTO document_versions(id, document_id, version, content_sha256, raw_text,"
                " normalized_text, normalization_report, detector_version, actor_principal_id,"
                " parent_version_id, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    version_id,
                    doc_id,
                    version_number,
                    content_digest,
                    text,
                    norm.normalized,
                    json.dumps(norm.report, default=str),
                    DETECTOR_VERSION,
                    self._actor_fk(conn, actor.id),
                    parent_version_id,
                    ts,
                ),
            )

            outcomes: list[ChunkOutcome] = []
            all_findings: list[dict[str, Any]] = []
            all_claims: list[dict[str, Any]] = []
            all_conflicts: list[dict[str, Any]] = []
            manifest_items: list[tuple[str, str]] = []

            for span in spans:
                chunk_id = new_id("chk")
                report: ScanReport = scan(
                    normalize_text(span.raw_text)
                )  # rescan the chunk so spans are chunk-local and offsets are exact

                chunk_claims = extract_claims(
                    span.normalized_text,
                    authority_tier=trust_tier,
                    source_id=source_id,
                    chunk_id=chunk_id,
                    default_effective_from=parse(eff),
                )
                conflicts: list[ClaimConflict] = []
                for claim in chunk_claims:
                    for other in existing_claims:
                        conflict = compare_claims(claim, other)
                        if conflict is not None:
                            conflicts.append(conflict)

                outcome: PolicyOutcome = decide_write(
                    report,
                    source_trust_tier=trust_tier,
                    conflicts=conflicts,
                    config=self.config,
                )

                conn.execute(
                    "INSERT INTO chunks(id, document_version_id, ordinal, raw_start, raw_end, text,"
                    " normalized_text, text_sha256, state, risk_score, max_severity, created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        chunk_id,
                        version_id,
                        span.ordinal,
                        span.raw_start,
                        span.raw_end,
                        span.raw_text,
                        span.normalized_text,
                        __import__("hashlib").sha256(span.raw_text.encode("utf-8")).hexdigest(),
                        outcome.state,
                        outcome.risk_score,
                        report.max_severity,
                        ts,
                    ),
                )
                manifest_items.append((ManifestStore.chunk_key(chunk_id), span.raw_text))

                # Defence in depth: only active chunks are indexed at write time, AND the retrieval
                # SQL independently excludes non-active states. Either layer alone would block
                # poison; the tests prove the second one works with the first bypassed.
                if outcome.state == "active":
                    self._index(conn, chunk_id, span.normalized_text)

                for finding in report.findings:
                    conn.execute(
                        "INSERT INTO risk_findings(id, chunk_id, document_version_id, rule_id,"
                        " rule_family, severity, confidence, confidence_semantics, evidence_start,"
                        " evidence_end, evidence_text, evidence_space, normalization_applied,"
                        " mitigated_by, detector_version, created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            new_id("rsk"),
                            chunk_id,
                            version_id,
                            finding.rule_id,
                            finding.rule_family,
                            finding.severity,
                            finding.confidence,
                            finding.confidence_semantics,
                            span.raw_start + finding.evidence_start,
                            span.raw_start + finding.evidence_end,
                            finding.evidence_text,
                            finding.evidence_space,
                            finding.normalization_applied,
                            finding.mitigated_by,
                            finding.detector_version,
                            ts,
                        ),
                    )
                    payload = finding.as_dict()
                    payload["chunk_id"] = chunk_id
                    payload["evidence_start"] = span.raw_start + finding.evidence_start
                    payload["evidence_end"] = span.raw_start + finding.evidence_end
                    all_findings.append(payload)

                for claim in chunk_claims:
                    claim.id = new_id("clm")
                    conn.execute(
                        "INSERT INTO claims(id, document_version_id, chunk_id, tenant_id, source_id,"
                        " subject, attribute, region, customer_tier, value_number, value_text, unit,"
                        " authority_tier, effective_from, effective_to, system_recorded_from,"
                        " system_recorded_to, evidence_start, evidence_end, created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL,?,?,?)",
                        (
                            claim.id,
                            version_id,
                            chunk_id,
                            actor.tenant_id,
                            source_id,
                            claim.subject,
                            claim.attribute,
                            claim.region,
                            claim.customer_tier,
                            claim.value_days,
                            claim.value_text,
                            claim.unit,
                            trust_tier,
                            iso(claim.effective_from),
                            ts,
                            span.raw_start + claim.evidence_start,
                            span.raw_start + claim.evidence_end,
                            ts,
                        ),
                    )
                    all_claims.append(claim.as_dict())

                for conflict in conflicts:
                    conflict_id = new_id("cfl")
                    # A duplicate (claim_a, claim_b) pair is a UNIQUE violation and simply means
                    # the conflict is already recorded.
                    with contextlib.suppress(sqlite3.IntegrityError):
                        conn.execute(
                            "INSERT INTO conflicts(id, tenant_id, claim_a_id, claim_b_id, kind,"
                            " status, detected_at, reason) VALUES(?,?,?,?,?, 'needs_review', ?, ?)",
                            (
                                conflict_id,
                                actor.tenant_id,
                                conflict.incoming.id,
                                conflict.existing.id,
                                conflict.kind,
                                ts,
                                conflict.detail,
                            ),
                        )
                    all_conflicts.append(
                        {
                            "id": conflict_id,
                            "kind": conflict.kind,
                            "unauthorized": conflict.unauthorized,
                            "authority_delta": conflict.authority_delta,
                            "detail": conflict.detail,
                            "incoming_claim": conflict.incoming.as_dict(),
                            "existing_claim": conflict.existing.as_dict(),
                        }
                    )

                outcomes.append(
                    ChunkOutcome(
                        chunk_id=chunk_id,
                        ordinal=span.ordinal,
                        decision=outcome.decision,
                        state=outcome.state,
                        reasons=outcome.reasons,
                        risk_score=outcome.risk_score,
                        max_severity=report.max_severity,
                        rule_ids=sorted({f.rule_id for f in report.findings}),
                        raw_span=(span.raw_start, span.raw_end),
                        preview=span.raw_text[:280],
                    )
                )

            # Document-level roll-up and the version's validity row.
            states = {o.state for o in outcomes}
            worst = max(outcomes, key=lambda o: _DECISION_RANK.get(o.decision, 0))
            if states == {"active"}:
                doc_state = "ACTIVE"
                version_state = "active"
            elif "active" not in states:
                doc_state = worst.state.upper()
                version_state = worst.state
            else:
                doc_state = "PARTIALLY_WITHHELD"
                version_state = "active"

            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?,?,?,NULL,?,NULL,?,?,?)",
                (
                    new_id("vvl"),
                    version_id,
                    version_state,
                    eff,
                    ts,
                    self._actor_fk(conn, actor.id),
                    f"ingest decision {worst.decision}",
                    ts,
                ),
            )

            # A new ACTIVE version of an existing document supersedes its predecessor in valid time
            # while the predecessor's prior belief stays queryable in system time.
            if parent_version_id and version_state == "active":
                self._supersede_versions(
                    conn,
                    document_id=doc_id,
                    keep_version_id=version_id,
                    effective_to=eff,
                    actor=actor,
                    reason=f"superseded by version {version_number}",
                )

            audit.record(
                conn,
                action="document.ingest",
                actor_principal_id=actor.id,
                tenant_id=actor.tenant_id,
                target_type="document_version",
                target_id=version_id,
                parent_version_id=parent_version_id,
                detail={
                    "source_id": source_id,
                    "document_id": doc_id,
                    "version": version_number,
                    "content_sha256": content_digest,
                    "document_state": doc_state,
                    "chunk_states": {o.chunk_id: o.state for o in outcomes},
                    "rule_ids": sorted({r for o in outcomes for r in o.rule_ids}),
                    "ignored_privileged_fields": sorted(set(ignored_privileged_fields)),
                },
            )

        # Manifests are written after the content transaction commits; see class docstring for why
        # that ordering still fails safe.
        self.manifests.put_many(manifest_items)
        self.manifests.put(ManifestStore.version_key(version_id), text)

        return IngestResult(
            document_id=doc_id,
            version_id=version_id,
            version=version_number,
            source_id=source_id,
            content_sha256=content_digest,
            state=doc_state,
            decision=worst.decision,
            chunks=outcomes,
            findings=all_findings,
            claims=all_claims,
            conflicts=all_conflicts,
            normalization_report=norm.report,
            ignored_privileged_fields=sorted(set(ignored_privileged_fields)),
            effective_from=eff,
        )

    # ------------------------------------------------------------------ retrieval -------------
    def retrieve(
        self,
        actor: Principal,
        *,
        query: str,
        limit: int = 5,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
        include_trace: bool = False,
        ignored_privileged_fields: Sequence[str] = (),
    ) -> RetrievalResult:
        """Enforcement point #2. Always logs an exposure row, including on a fail-closed result."""
        run_id = new_id("run")
        with self.db.connect() as conn:
            result = guarded_search(
                conn,
                self.manifests,
                actor,
                query=query,
                run_id=run_id,
                limit=limit,
                as_of_valid=as_of_valid,
                as_of_recorded=as_of_recorded,
                config=self.config,
                include_trace=include_trace,
            )

        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO retrieval_exposures(id, run_id, tenant_id, principal_id, query,"
                " as_of_valid, as_of_recorded, candidate_count, eligible_chunk_ids, excluded,"
                " returned_chunk_ids, guard_enforced, fail_closed, latency_ms, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new_id("exp"),
                    run_id,
                    actor.tenant_id,
                    actor.id,
                    query,
                    result.as_of_valid,
                    result.as_of_recorded,
                    result.candidate_count,
                    json.dumps(result.chunk_ids()),
                    json.dumps([e.as_dict() for e in (result.trace or [])]),
                    json.dumps(result.chunk_ids()),
                    1,
                    1 if result.fail_closed else 0,
                    result.latency_ms,
                    iso(now()),
                ),
            )
            if result.integrity_alerts:
                for alert in result.integrity_alerts:
                    audit.record(
                        conn,
                        action="integrity.alert",
                        actor_principal_id=actor.id,
                        tenant_id=actor.tenant_id,
                        target_type="chunk",
                        target_id=str(alert.get("chunk_id")),
                        detail=alert,
                    )
            if ignored_privileged_fields:
                audit.record(
                    conn,
                    action="identity.forged_fields_ignored",
                    actor_principal_id=actor.id,
                    tenant_id=actor.tenant_id,
                    target_type="retrieval",
                    target_id=run_id,
                    detail={"ignored": sorted(set(ignored_privileged_fields))},
                )
        return result

    def build_context_pack(
        self,
        actor: Principal,
        *,
        query: str,
        limit: int = 5,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
        include_answer: bool = True,
    ) -> ContextPack:
        """Enforcement point #3. Only eligible chunks reach the pack; empty packs fail safe."""
        result = self.retrieve(
            actor,
            query=query,
            limit=limit,
            as_of_valid=as_of_valid,
            as_of_recorded=as_of_recorded,
        )
        return build_context_pack(result, include_answer=include_answer)

    def unguarded_baseline(
        self, actor: Principal, *, query: str, limit: int = 5, same_tenant_only: bool = True
    ) -> dict[str, Any]:
        """Labelled measurement baseline. Admin only, and only when explicitly enabled."""
        actor.require("admin")
        if not self.config.enable_unguarded_baseline:
            raise AuthorizationError(
                "the unguarded baseline is disabled; set MF_ENABLE_UNGUARDED_BASELINE=1 to enable "
                "it for measurement and demonstration"
            )
        with self.db.connect() as conn:
            rows = unguarded_search_for_baseline(
                conn,
                query=query,
                tenant_id=actor.tenant_id if same_tenant_only else None,
                limit=limit,
            )
        return {
            "baseline": "naive_unguarded_fts",
            "is_memory_firewall_output": False,
            "warning": (
                "This is a deliberately unprotected query used only to measure and demonstrate "
                "what an unguarded pipeline would have exposed on the same corpus. It is not a "
                "Memory Firewall retrieval result."
            ),
            "query": query,
            "hits": rows,
        }

    # ------------------------------------------------------------------ review ----------------
    def review(
        self,
        actor: Principal,
        *,
        target_type: str,
        target_id: str,
        decision: str,
        reason: str,
        effective_from: datetime | None = None,
        revised_text: str | None = None,
    ) -> ReviewOutcome:
        """The one shared reviewer-transition service used by both the API and the SDK."""
        actor.require("reviewer")
        if target_type not in {"chunk", "version"}:
            raise ValidationError("target_type must be 'chunk' or 'version'")
        if decision not in {"approve", "reject", "revise"}:
            raise ValidationError("decision must be approve, reject or revise")
        if not reason or not reason.strip():
            raise ValidationError("a review reason is required and is stored in the audit trail")

        ts = iso(now())
        reindexed = 0
        superseded: list[str] = []
        new_version_id: str | None = None
        eff = iso(to_utc(effective_from)) if effective_from else None

        with self.db.transaction() as conn:
            if target_type == "chunk":
                row = conn.execute(
                    "SELECT c.id, c.state, c.normalized_text, c.document_version_id, dv.document_id,"
                    " s.tenant_id, s.id AS source_id FROM chunks c"
                    " JOIN document_versions dv ON dv.id = c.document_version_id"
                    " JOIN documents d ON d.id = dv.document_id"
                    " JOIN sources s ON s.id = d.source_id WHERE c.id = ?",
                    (target_id,),
                ).fetchone()
                if row is None or row["tenant_id"] != actor.tenant_id:
                    raise NotFoundError("review target not found")
                prev_state = row["state"]
                new_state = TRANSITIONS.get((prev_state, decision))
                if new_state is None:
                    raise ConflictError(
                        f"transition ({prev_state}, {decision}) is not permitted; see "
                        "docs/THREAT_MODEL.md for the transition table"
                    )
                conn.execute("UPDATE chunks SET state=? WHERE id=?", (new_state, target_id))
                if new_state == "active":
                    self._index(conn, target_id, row["normalized_text"])
                    reindexed = 1
                    # Approving a chunk has to lift its *version's* gate too, otherwise a reviewer
                    # can approve the only chunk of a quarantined single-chunk document and it
                    # stays unretrievable with no indication why. The version transition is
                    # recorded as its own append-only validity row so the audit trail still shows
                    # two distinct decisions.
                    current = self._current_validity(conn, row["document_version_id"])
                    if current is not None and current["state"] in {
                        "quarantined",
                        "review_required",
                    }:
                        conn.execute(
                            "UPDATE version_validity SET system_recorded_to=? WHERE id=?",
                            (ts, current["id"]),
                        )
                        conn.execute(
                            "INSERT INTO version_validity(id, document_version_id, state,"
                            " effective_from, effective_to, system_recorded_from,"
                            " system_recorded_to, actor_principal_id, reason, created_at)"
                            " VALUES(?,?, 'active', ?,?,?,NULL,?,?,?)",
                            (
                                new_id("vvl"),
                                row["document_version_id"],
                                current["effective_from"],
                                current["effective_to"],
                                ts,
                                self._actor_fk(conn, actor.id),
                                f"version gate opened by chunk approval ({target_id})",
                                ts,
                            ),
                        )
                        audit.record(
                            conn,
                            action="review.version_gate_opened",
                            actor_principal_id=actor.id,
                            tenant_id=row["tenant_id"],
                            target_type="version",
                            target_id=row["document_version_id"],
                            detail={
                                "prev_state": current["state"],
                                "new_state": "active",
                                "triggered_by_chunk": target_id,
                            },
                        )
                else:
                    self._unindex(conn, [target_id])
                    reindexed = 1
                tenant = row["tenant_id"]
                version_id = row["document_version_id"]
            else:
                row = conn.execute(
                    "SELECT dv.id, dv.document_id, dv.version, s.tenant_id, s.id AS source_id"
                    " FROM document_versions dv JOIN documents d ON d.id = dv.document_id"
                    " JOIN sources s ON s.id = d.source_id WHERE dv.id = ?",
                    (target_id,),
                ).fetchone()
                if row is None or row["tenant_id"] != actor.tenant_id:
                    raise NotFoundError("review target not found")
                current = self._current_validity(conn, target_id)
                if current is None:
                    raise ConflictError("version has no open validity row")
                prev_state = current["state"]
                new_state = TRANSITIONS.get((prev_state, decision))
                if new_state is None:
                    raise ConflictError(
                        f"transition ({prev_state}, {decision}) is not permitted; see "
                        "docs/THREAT_MODEL.md for the transition table"
                    )

                # Close the current belief in system time and record the new one. Never mutate.
                conn.execute(
                    "UPDATE version_validity SET system_recorded_to=? WHERE id=?",
                    (ts, current["id"]),
                )
                conn.execute(
                    "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                    " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                    " reason, created_at) VALUES(?,?,?,?,?,?,NULL,?,?,?)",
                    (
                        new_id("vvl"),
                        target_id,
                        new_state,
                        eff or current["effective_from"],
                        current["effective_to"],
                        ts,
                        self._actor_fk(conn, actor.id),
                        reason,
                        ts,
                    ),
                )
                if new_state == "active":
                    # promote this version's chunks that are not individually blocked
                    chunk_rows = conn.execute(
                        "SELECT id, state, normalized_text FROM chunks WHERE document_version_id=?",
                        (target_id,),
                    ).fetchall()
                    for chunk in chunk_rows:
                        if chunk["state"] in {"quarantined", "review_required"}:
                            conn.execute(
                                "UPDATE chunks SET state='active' WHERE id=?", (chunk["id"],)
                            )
                        if chunk["state"] != "rejected":
                            self._index(conn, chunk["id"], chunk["normalized_text"])
                            reindexed += 1
                    superseded = self._supersede_versions(
                        conn,
                        document_id=row["document_id"],
                        keep_version_id=target_id,
                        effective_to=eff or current["effective_from"],
                        actor=actor,
                        reason=f"superseded by approved version {row['version']}",
                    )
                    self._supersede_claims(
                        conn,
                        version_id=target_id,
                        tenant_id=actor.tenant_id,
                        effective_to=eff or current["effective_from"],
                        ts=ts,
                    )
                else:
                    chunk_ids = [
                        r["id"]
                        for r in conn.execute(
                            "SELECT id FROM chunks WHERE document_version_id=?", (target_id,)
                        ).fetchall()
                    ]
                    conn.execute(
                        "UPDATE chunks SET state=? WHERE document_version_id=?",
                        (new_state if new_state != "superseded" else "superseded", target_id),
                    )
                    self._unindex(conn, chunk_ids)
                    reindexed = len(chunk_ids)
                tenant = row["tenant_id"]
                version_id = target_id

            review_id = new_id("rvw")
            conn.execute(
                "INSERT INTO review_decisions(id, target_type, target_id, decision,"
                " reviewer_principal_id, reason, prev_state, new_state, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    review_id,
                    target_type,
                    target_id,
                    decision,
                    self._actor_fk(conn, actor.id) or actor.id,
                    reason,
                    prev_state,
                    new_state,
                    ts,
                ),
            )
            audit.record(
                conn,
                action=f"review.{decision}",
                actor_principal_id=actor.id,
                tenant_id=tenant,
                target_type=target_type,
                target_id=target_id,
                parent_version_id=version_id,
                detail={
                    "prev_state": prev_state,
                    "new_state": new_state,
                    "reason": reason,
                    "reindexed_chunks": reindexed,
                    "effective_from": eff,
                },
            )

        # A 'revise' produces a brand-new version that is re-screened from scratch: approval never
        # grants a free pass to edited text (Scenario E, memory resurrection).
        if decision == "revise" and revised_text:
            with self.db.connect() as conn:
                info = conn.execute(
                    "SELECT dv.document_id, d.source_id FROM document_versions dv"
                    " JOIN documents d ON d.id = dv.document_id WHERE dv.id = ?",
                    (version_id,),
                ).fetchone()
            if info is not None:
                revised = self.ingest(
                    actor,
                    source_id=info["source_id"],
                    text=revised_text,
                    document_id=info["document_id"],
                    effective_from=effective_from,
                )
                new_version_id = revised.version_id

        return ReviewOutcome(
            target_type=target_type,
            target_id=target_id,
            decision=decision,
            prev_state=prev_state,
            new_state=new_state,
            reviewer=actor.id,
            reason=reason,
            review_id=review_id,
            reindexed_chunks=reindexed,
            superseded_versions=superseded,
            new_version_id=new_version_id,
            effective_from=eff,
        )

    def resolve_conflict(
        self, actor: Principal, conflict_id: str, *, status: str, reason: str
    ) -> dict[str, Any]:
        actor.require("reviewer")
        if status not in {"resolved_supersede", "resolved_dismissed", "resolved_rejected"}:
            raise ValidationError("unknown conflict resolution status")
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM conflicts WHERE id = ? AND tenant_id = ?",
                (conflict_id, actor.tenant_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("conflict not found")
            conn.execute(
                "UPDATE conflicts SET status=?, resolved_at=?, resolver_id=?, reason=? WHERE id=?",
                (
                    status,
                    iso(now()),
                    self._actor_fk(conn, actor.id) or actor.id,
                    reason,
                    conflict_id,
                ),
            )
            audit.record(
                conn,
                action="conflict.resolve",
                actor_principal_id=actor.id,
                tenant_id=actor.tenant_id,
                target_type="conflict",
                target_id=conflict_id,
                detail={"status": status, "reason": reason},
            )
        return {"conflict_id": conflict_id, "status": status}

    # ------------------------------------------------------------------ snapshots -------------
    def snapshot(
        self,
        actor: Principal,
        label: str,
        note: str = "",
        *,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
    ) -> dict[str, Any]:
        actor.require("reviewer")
        snapshot_id = new_id("snp")
        valid = iso(to_utc(as_of_valid)) if as_of_valid else iso(now())
        recorded = iso(to_utc(as_of_recorded)) if as_of_recorded else iso(now())
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO snapshots(id, label, tenant_id, created_by, as_of_valid,"
                " as_of_recorded, note, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    snapshot_id,
                    label,
                    actor.tenant_id,
                    self._actor_fk(conn, actor.id) or actor.id,
                    valid,
                    recorded,
                    note,
                    iso(now()),
                ),
            )
            audit.record(
                conn,
                action="snapshot.create",
                actor_principal_id=actor.id,
                tenant_id=actor.tenant_id,
                target_type="snapshot",
                target_id=snapshot_id,
                detail={"label": label, "as_of_valid": valid, "as_of_recorded": recorded},
            )
        return {
            "snapshot_id": snapshot_id,
            "label": label,
            "as_of_valid": valid,
            "as_of_recorded": recorded,
            "note": note,
        }

    def replay_snapshot(
        self, actor: Principal, snapshot_id: str, query: str, limit: int = 5
    ) -> dict[str, Any]:
        """Replay a query as of a snapshot's two time coordinates.

        The replay runs the *same guarded search* with historical coordinates. It therefore shows
        what an authorised reader could have seen then; it never re-promotes rejected or quarantined
        content, and it cannot reconstruct hidden model state — only the memory layer.
        """
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM snapshots WHERE id = ? AND tenant_id = ?",
                (snapshot_id, actor.tenant_id),
            ).fetchone()
        if row is None:
            raise NotFoundError("snapshot not found")
        # The historical view uses BOTH of the snapshot's coordinates. The "current" view reuses the
        # snapshot's *valid* time and only moves the *recorded* time to now, so the diff isolates
        # what the system has since learned about that same moment in force — which is the question
        # a time machine is actually asked ("what changed our answer, and which revision did it?").
        historical = self.retrieve(
            actor,
            query=query,
            limit=limit,
            as_of_valid=parse(row["as_of_valid"]),
            as_of_recorded=parse(row["as_of_recorded"]),
        )
        current = self.retrieve(
            actor, query=query, limit=limit, as_of_valid=parse(row["as_of_valid"])
        )
        hist_ids = set(historical.chunk_ids())
        cur_ids = set(current.chunk_ids())
        return {
            "snapshot_id": snapshot_id,
            "label": row["label"],
            "historical_view": True,
            "view_label": (
                f"Historical view as of valid-time {row['as_of_valid']} and recorded-time "
                f"{row['as_of_recorded']}. Read-only replay; no content was re-promoted."
            ),
            "as_of_valid": row["as_of_valid"],
            "as_of_recorded": row["as_of_recorded"],
            "coordinates": {
                "historical": {"valid": row["as_of_valid"], "recorded": row["as_of_recorded"]},
                "current": {"valid": row["as_of_valid"], "recorded": "now"},
            },
            "query": query,
            "historical": historical.as_dict(),
            "current": current.as_dict(),
            "diff": {
                "only_in_historical": sorted(hist_ids - cur_ids),
                "only_in_current": sorted(cur_ids - hist_ids),
                "unchanged": sorted(hist_ids & cur_ids),
                "answer_context_changed": hist_ids != cur_ids,
                "historical_citations": sorted({c.citation for c in historical.context_chunks}),
                "current_citations": sorted({c.citation for c in current.context_chunks}),
                "revisions_changed": sorted(
                    {c.citation for c in historical.context_chunks}
                    ^ {c.citation for c in current.context_chunks}
                ),
            },
        }

    # ------------------------------------------------------------------ read models -----------
    def quarantine_queue(
        self, actor: Principal, *, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Chunks withheld from active memory, with their evidence. Reviewer+ only."""
        actor.require("reviewer")
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT c.id AS chunk_id, c.state, c.text, c.risk_score, c.max_severity,"
                " c.raw_start, c.raw_end, c.created_at, dv.id AS version_id, dv.version,"
                " d.id AS document_id, d.title, s.id AS source_id, s.trust_tier"
                " FROM chunks c"
                " JOIN document_versions dv ON dv.id = c.document_version_id"
                " JOIN documents d ON d.id = dv.document_id"
                " JOIN sources s ON s.id = d.source_id"
                " WHERE s.tenant_id = ? AND c.state IN ('quarantined','review_required','rejected')"
                " ORDER BY c.risk_score DESC, c.created_at DESC LIMIT ? OFFSET ?",
                (actor.tenant_id, min(limit, 200), max(0, offset)),
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                findings = conn.execute(
                    "SELECT rule_id, rule_family, severity, confidence, confidence_semantics,"
                    " evidence_start, evidence_end, evidence_text, mitigated_by,"
                    " normalization_applied, detector_version FROM risk_findings"
                    " WHERE chunk_id = ? ORDER BY severity DESC",
                    (r["chunk_id"],),
                ).fetchall()
                item = dict(r)
                item["findings"] = [dict(f) for f in findings]
                # Pre-escaped, span-highlighted preview. The chunk's own raw offsets are absolute
                # within the document, so they are rebased to chunk-local coordinates first.
                base = int(r["raw_start"] or 0)
                spans = [
                    (int(f["evidence_start"]) - base, int(f["evidence_end"]) - base)
                    for f in findings
                ]
                item["preview_html"] = highlight_spans(r["text"], spans)
                item["preview_text"] = truncate_preview(r["text"])
                out.append(item)
        return out

    def conflicts(self, actor: Principal, *, status: str | None = None) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            sql = (
                "SELECT cf.*, "
                " ca.value_number AS incoming_value, ca.authority_tier AS incoming_authority,"
                " ca.source_id AS incoming_source, ca.region AS region,"
                " ca.customer_tier AS customer_tier, ca.chunk_id AS incoming_chunk,"
                " ca.evidence_start AS incoming_evidence_start,"
                " ca.evidence_end AS incoming_evidence_end,"
                " cb.value_number AS existing_value, cb.authority_tier AS existing_authority,"
                " cb.source_id AS existing_source, cb.chunk_id AS existing_chunk"
                " FROM conflicts cf"
                " JOIN claims ca ON ca.id = cf.claim_a_id"
                " JOIN claims cb ON cb.id = cf.claim_b_id"
                " WHERE cf.tenant_id = ?"
            )
            params: list[Any] = [actor.tenant_id]
            if status:
                sql += " AND cf.status = ?"
                params.append(status)
            sql += " ORDER BY cf.detected_at DESC LIMIT 200"
            return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]

    def ledger(self, actor: Principal, *, limit: int = 100) -> list[dict[str, Any]]:
        """Memory ledger: every version with its full validity history, newest first."""
        with self.db.connect() as conn:
            versions = conn.execute(
                "SELECT dv.id AS version_id, dv.version, dv.content_sha256, dv.created_at,"
                " dv.parent_version_id, dv.actor_principal_id, d.id AS document_id, d.title,"
                " d.status AS document_status, s.id AS source_id, s.trust_tier, s.status AS"
                " source_status FROM document_versions dv"
                " JOIN documents d ON d.id = dv.document_id"
                " JOIN sources s ON s.id = d.source_id"
                " WHERE s.tenant_id = ? ORDER BY dv.created_at DESC, dv.version DESC LIMIT ?",
                (actor.tenant_id, min(limit, 500)),
            ).fetchall()
            out: list[dict[str, Any]] = []
            for v in versions:
                validity = conn.execute(
                    "SELECT state, effective_from, effective_to, system_recorded_from,"
                    " system_recorded_to, reason, actor_principal_id FROM version_validity"
                    " WHERE document_version_id = ? ORDER BY system_recorded_from",
                    (v["version_id"],),
                ).fetchall()
                counts = conn.execute(
                    "SELECT state, COUNT(*) AS n FROM chunks WHERE document_version_id = ?"
                    " GROUP BY state",
                    (v["version_id"],),
                ).fetchall()
                item = dict(v)
                item["validity"] = [dict(r) for r in validity]
                item["chunk_states"] = {r["state"]: r["n"] for r in counts}
                out.append(item)
        return out

    def sources(self, actor: Principal) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM documents d WHERE d.source_id = s.id) AS documents"
                " FROM sources s WHERE s.tenant_id = ? ORDER BY s.created_at",
                (actor.tenant_id,),
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                acl = [
                    a["principal_id"]
                    for a in conn.execute(
                        "SELECT principal_id FROM source_acl WHERE source_id = ?"
                        " AND permission='read'",
                        (r["id"],),
                    ).fetchall()
                ]
                item = dict(r)
                item["read_acl"] = acl
                out.append(item)
        return out

    def document_versions(self, actor: Principal, document_id: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            doc = conn.execute(
                "SELECT d.*, s.tenant_id, s.trust_tier FROM documents d"
                " JOIN sources s ON s.id = d.source_id WHERE d.id = ?",
                (document_id,),
            ).fetchone()
            if doc is None or doc["tenant_id"] != actor.tenant_id:
                raise NotFoundError("document not found")
            versions = conn.execute(
                "SELECT id, version, content_sha256, created_at, actor_principal_id,"
                " parent_version_id FROM document_versions WHERE document_id = ? ORDER BY version",
                (document_id,),
            ).fetchall()
            out = {"document": dict(doc), "versions": []}
            for v in versions:
                validity = conn.execute(
                    "SELECT state, effective_from, effective_to, system_recorded_from,"
                    " system_recorded_to, reason FROM version_validity"
                    " WHERE document_version_id = ? ORDER BY system_recorded_from",
                    (v["id"],),
                ).fetchall()
                item = dict(v)
                item["validity"] = [dict(r) for r in validity]
                # Raw text is only served to reviewers: a reader must not read quarantined text.
                if actor.is_reviewer:
                    full = conn.execute(
                        "SELECT raw_text FROM document_versions WHERE id = ?", (v["id"],)
                    ).fetchone()
                    item["raw_text"] = full["raw_text"]
                out["versions"].append(item)
        return out

    def exposures(
        self, actor: Principal, *, limit: int = 50, run_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieval traces. Exclusion detail is admin-only; readers see their own runs redacted."""
        with self.db.connect() as conn:
            sql = "SELECT * FROM retrieval_exposures WHERE tenant_id = ?"
            params: list[Any] = [actor.tenant_id]
            if not actor.is_admin:
                sql += " AND principal_id = ?"
                params.append(actor.id)
            if run_id:
                sql += " AND run_id = ?"
                params.append(run_id)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(min(limit, 200))
            rows = conn.execute(sql, tuple(params)).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            for key in ("eligible_chunk_ids", "returned_chunk_ids", "excluded"):
                try:
                    item[key] = json.loads(item.get(key) or "[]")
                except json.JSONDecodeError:
                    item[key] = []
            if not actor.is_admin:
                item["excluded"] = "redacted: exclusion detail is visible to tenant admins only"
            out.append(item)
        return out

    def audit_log(
        self, actor: Principal, *, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        actor.require("reviewer")
        with self.db.connect() as conn:
            return audit.recent(conn, tenant_id=actor.tenant_id, limit=limit, offset=offset)

    def stats(self, actor: Principal) -> dict[str, Any]:
        with self.db.connect() as conn:

            def scalar(sql: str, params: tuple = ()) -> int:
                row = conn.execute(sql, params).fetchone()
                return int(row[0] or 0)

            t = actor.tenant_id
            chunk_states = {
                r["state"]: r["n"]
                for r in conn.execute(
                    "SELECT c.state, COUNT(*) AS n FROM chunks c"
                    " JOIN document_versions dv ON dv.id = c.document_version_id"
                    " JOIN documents d ON d.id = dv.document_id"
                    " JOIN sources s ON s.id = d.source_id WHERE s.tenant_id = ?"
                    " GROUP BY c.state",
                    (t,),
                ).fetchall()
            }
            return {
                "tenant_id": t,
                "sources": scalar("SELECT COUNT(*) FROM sources WHERE tenant_id=?", (t,)),
                "documents": scalar(
                    "SELECT COUNT(*) FROM documents d JOIN sources s ON s.id=d.source_id"
                    " WHERE s.tenant_id=?",
                    (t,),
                ),
                "chunk_states": chunk_states,
                "active_chunks": chunk_states.get("active", 0),
                "withheld_chunks": sum(v for k, v in chunk_states.items() if k != "active"),
                "open_conflicts": scalar(
                    "SELECT COUNT(*) FROM conflicts WHERE tenant_id=? AND status='needs_review'",
                    (t,),
                ),
                "retrievals": scalar(
                    "SELECT COUNT(*) FROM retrieval_exposures WHERE tenant_id=?", (t,)
                ),
                "snapshots": scalar("SELECT COUNT(*) FROM snapshots WHERE tenant_id=?", (t,)),
                "manifest_entries": self.manifests.count(),
                "detector_version": DETECTOR_VERSION,
                "policy_revision": POLICY_REVISION,
            }

    # ------------------------------------------------------------------ internals -------------
    @staticmethod
    def _index(conn: sqlite3.Connection, chunk_id: str, text: str) -> None:
        conn.execute("DELETE FROM fts_chunks WHERE chunk_id = ?", (chunk_id,))
        conn.execute("INSERT INTO fts_chunks(text, chunk_id) VALUES(?, ?)", (text, chunk_id))

    @staticmethod
    def _unindex(conn: sqlite3.Connection, chunk_ids: Sequence[str]) -> None:
        for chunk_id in chunk_ids:
            conn.execute("DELETE FROM fts_chunks WHERE chunk_id = ?", (chunk_id,))

    def _require_source(
        self,
        conn: sqlite3.Connection,
        source_id: str,
        actor: Principal,
        *,
        require_active: bool = False,
    ) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        # Cross-tenant and nonexistent are the same answer on purpose: otherwise the error code is
        # an existence oracle for another tenant's source names (MF-07).
        if row is None or (row["tenant_id"] != actor.tenant_id and actor.tenant_id != "*"):
            raise NotFoundError("source not found")
        if require_active and row["status"] != "active":
            raise PolicyError(f"source '{source_id}' is {row['status']} and cannot accept content")
        return row

    @staticmethod
    def _current_validity(conn: sqlite3.Connection, version_id: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM version_validity WHERE document_version_id = ?"
            " AND system_recorded_to IS NULL ORDER BY system_recorded_from DESC LIMIT 1",
            (version_id,),
        ).fetchone()

    def _supersede_versions(
        self,
        conn: sqlite3.Connection,
        *,
        document_id: str,
        keep_version_id: str,
        effective_to: str,
        actor: Principal,
        reason: str,
    ) -> list[str]:
        """Close other active versions of this document in valid time, preserving system time."""
        ts = iso(now())
        rows = conn.execute(
            "SELECT vv.id, vv.document_version_id, vv.state, vv.effective_from, vv.effective_to"
            " FROM version_validity vv JOIN document_versions dv"
            " ON dv.id = vv.document_version_id"
            " WHERE dv.document_id = ? AND vv.document_version_id != ?"
            " AND vv.system_recorded_to IS NULL AND vv.state = 'active'",
            (document_id, keep_version_id),
        ).fetchall()
        superseded: list[str] = []
        for row in rows:
            conn.execute(
                "UPDATE version_validity SET system_recorded_to=? WHERE id=?", (ts, row["id"])
            )
            conn.execute(
                "INSERT INTO version_validity(id, document_version_id, state, effective_from,"
                " effective_to, system_recorded_from, system_recorded_to, actor_principal_id,"
                " reason, created_at) VALUES(?,?, 'active', ?,?,?,NULL,?,?,?)",
                (
                    new_id("vvl"),
                    row["document_version_id"],
                    row["effective_from"],
                    effective_to,
                    ts,
                    self._actor_fk(conn, actor.id),
                    reason,
                    ts,
                ),
            )
            superseded.append(row["document_version_id"])
        return superseded

    def _supersede_claims(
        self,
        conn: sqlite3.Connection,
        *,
        version_id: str,
        tenant_id: str,
        effective_to: str,
        ts: str,
    ) -> None:
        """Close earlier claims on the same key when a newer authoritative claim takes effect."""
        incoming = conn.execute(
            "SELECT * FROM claims WHERE document_version_id = ?", (version_id,)
        ).fetchall()
        for claim in incoming:
            conn.execute(
                "UPDATE claims SET effective_to = ?, system_recorded_to = ?"
                " WHERE tenant_id = ? AND subject = ? AND attribute = ? AND region = ?"
                " AND customer_tier = ? AND document_version_id != ? AND effective_to IS NULL"
                " AND system_recorded_to IS NULL",
                (
                    effective_to,
                    ts,
                    tenant_id,
                    claim["subject"],
                    claim["attribute"],
                    claim["region"],
                    claim["customer_tier"],
                    version_id,
                ),
            )

    @staticmethod
    def _active_claims(conn: sqlite3.Connection, tenant_id: str) -> list[Claim]:
        """Claims that currently stand: from an active chunk, active version, active source.

        A quarantined document's claim never becomes the baseline that future documents are compared
        against — otherwise poison would define the ground truth it is supposed to be caught against.
        """
        rows = conn.execute(
            "SELECT cl.* FROM claims cl"
            " JOIN chunks c ON c.id = cl.chunk_id"
            " JOIN document_versions dv ON dv.id = cl.document_version_id"
            " JOIN documents d ON d.id = dv.document_id"
            " JOIN sources s ON s.id = d.source_id"
            " JOIN version_validity vv ON vv.document_version_id = dv.id"
            "   AND vv.system_recorded_to IS NULL"
            " WHERE cl.tenant_id = ? AND cl.effective_to IS NULL AND cl.system_recorded_to IS NULL"
            "   AND c.state = 'active' AND vv.state = 'active' AND d.status = 'active'"
            "   AND s.status = 'active'",
            (tenant_id,),
        ).fetchall()
        out: list[Claim] = []
        for r in rows:
            out.append(
                Claim(
                    id=r["id"],
                    subject=r["subject"],
                    attribute=r["attribute"],
                    region=r["region"],
                    customer_tier=r["customer_tier"],
                    value_days=r["value_number"],
                    value_text=r["value_text"] or "",
                    unit=r["unit"] or "days",
                    evidence_start=int(r["evidence_start"] or 0),
                    evidence_end=int(r["evidence_end"] or 0),
                    effective_from=parse(r["effective_from"]),
                    authority_tier=r["authority_tier"],
                    source_id=r["source_id"],
                    chunk_id=r["chunk_id"] or "",
                )
            )
        return out


_DECISION_RANK = {
    "ALLOW": 0,
    "ALLOW_WITH_FLAGS": 1,
    "REVIEW_REQUIRED": 2,
    "QUARANTINE": 3,
    "REJECT": 4,
}
assert set(_DECISION_RANK) == set(DECISION_STATE)
