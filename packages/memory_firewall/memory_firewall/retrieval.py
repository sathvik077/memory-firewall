"""The pre-retrieval guard: enforcement point #2.

The whole product rests on one property: **a chunk that is not eligible can never be ranked,
counted, cited, previewed or returned.** The way that property is obtained here is that the gate is
part of the single SQL statement that does the search, not a Python filter applied to a result set
that was already assembled. There is no code path that selects candidates first and filters later,
which is why seeding poison directly into the index (MF-05 / MF-SEED-07) still returns nothing.

Layers, in order, every one of which can only *remove* rows:

1. **Permission-aware SQL.** Tenant, source status/expiry, per-principal read ACL, document status,
   chunk state, version state, valid-time interval and system-time interval are all predicates in
   the ``MATCH`` query itself.
2. **Trust floor.** An optional configured minimum source trust tier.
3. **Integrity recheck.** Every surviving chunk's text is re-hashed and compared with the expected
   digest in the side-store manifest. A mismatch or a *missing* manifest excludes the chunk and
   raises an integrity alert, because post-index mutation of the content DB is exactly the
   MF-SEED-11 scenario.
4. **Fail closed.** Any exception anywhere in the guard yields an empty result with
   ``fail_closed: true``. There is no branch in which an error produces unguarded memory.

Information leakage is treated as part of the gate, not a presentation concern: a reader's result
carries no excluded IDs, no excluded counts and no foreign metadata. ``candidate_count`` returned to
a reader is the count of *eligible* candidates only. The admin trace is a separate query, is itself
tenant-scoped, and is the only place exclusion reasons exist.

There is no cross-request cache anywhere in this module, so a revoked ACL or a tombstoned document
takes effect on the very next call with nothing to invalidate.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._version import POLICY_REVISION
from .clock import iso, now, to_utc
from .config import TRUST_ORDER, FirewallConfig
from .identity import Principal
from .integrity import ManifestStore

__all__ = [
    "ExclusionRecord",
    "RetrievalResult",
    "RetrievedChunk",
    "build_fts_query",
    "guarded_search",
    "unguarded_search_for_baseline",
]

_TOKEN = re.compile(r"[0-9A-Za-z_]+", re.UNICODE)

#: Dropped from search queries. An OR-of-tokens query is the right shape for a small corpus, but
#: without this a question like "What is the CEO's home address?" matches every document that
#: contains "is" or "the" and the caller gets a confidently irrelevant answer. Removing function
#: words is what makes "no eligible evidence" actually happen for an off-topic question — which is
#: the behaviour the fail-safe story depends on.
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "being",
        "by",
        "do",
        "does",
        "did",
        "for",
        "from",
        "had",
        "has",
        "have",
        "how",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "out",
        "over",
        "so",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "to",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "whom",
        "whose",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "can",
        "could",
        "should",
        "may",
        "might",
        "must",
        "about",
        "after",
        "before",
        "during",
        "under",
        "above",
        "please",
        "thanks",
    ]
)

# Columns selected by the guarded query. Kept in one place so the trace query cannot accidentally
# diverge from the real one.
_SELECT = """
    c.id              AS chunk_id,
    c.text            AS raw_text,
    c.normalized_text AS normalized_text,
    c.text_sha256     AS text_sha256,
    c.ordinal         AS ordinal,
    c.raw_start       AS raw_start,
    c.raw_end         AS raw_end,
    c.risk_score      AS risk_score,
    c.max_severity    AS max_severity,
    dv.id             AS version_id,
    dv.version        AS version,
    dv.content_sha256 AS content_sha256,
    d.id              AS document_id,
    d.title           AS title,
    d.uri             AS uri,
    s.id              AS source_id,
    s.trust_tier      AS trust_tier,
    s.tenant_id       AS tenant_id,
    vv.effective_from AS effective_from,
    vv.effective_to   AS effective_to,
    vv.system_recorded_from AS system_recorded_from
"""

# `s.expires_at` is compared against **valid** time, not recorded time: a source's authorisation
# expiring is a fact about the world on a date, so an as-of query into a period when the source was
# still authorised should see its content, while "now" must not.
_GUARDED_SQL = f"""
SELECT {_SELECT},
       bm25(fts_chunks) AS rank
FROM fts_chunks
JOIN chunks            c   ON c.id  = fts_chunks.chunk_id
JOIN document_versions dv  ON dv.id = c.document_version_id
JOIN documents         d   ON d.id  = dv.document_id
JOIN sources           s   ON s.id  = d.source_id
JOIN version_validity  vv  ON vv.document_version_id = dv.id
JOIN source_acl        acl ON acl.source_id = s.id
                          AND acl.principal_id = :principal
                          AND acl.permission = 'read'
WHERE fts_chunks MATCH :fts
  AND s.tenant_id = :tenant
  AND s.status    = 'active'
  AND (s.expires_at IS NULL OR s.expires_at > :as_of_valid)
  AND d.status    = 'active'
  AND c.state     = 'active'
  AND vv.state    = 'active'
  AND vv.system_recorded_from <= :as_of_recorded
  AND (vv.system_recorded_to IS NULL OR vv.system_recorded_to > :as_of_recorded)
  AND vv.effective_from <= :as_of_valid
  AND (vv.effective_to IS NULL OR vv.effective_to > :as_of_valid)
ORDER BY rank
LIMIT :limit
"""

# Admin-only forensic query. Same tenant restriction as the real query; everything else is a LEFT
# JOIN so that the reason a candidate was dropped can be computed and shown.
_TRACE_SQL = f"""
SELECT {_SELECT},
       bm25(fts_chunks) AS rank,
       s.status       AS source_status,
       s.expires_at   AS source_expires_at,
       d.status       AS document_status,
       c.state        AS chunk_state,
       vv.state       AS version_state,
       vv.system_recorded_to AS system_recorded_to,
       acl.principal_id AS acl_principal
FROM fts_chunks
JOIN chunks            c   ON c.id  = fts_chunks.chunk_id
JOIN document_versions dv  ON dv.id = c.document_version_id
JOIN documents         d   ON d.id  = dv.document_id
JOIN sources           s   ON s.id  = d.source_id
LEFT JOIN version_validity vv ON vv.document_version_id = dv.id
                             AND vv.system_recorded_from <= :as_of_recorded
                             AND (vv.system_recorded_to IS NULL OR vv.system_recorded_to > :as_of_recorded)
LEFT JOIN source_acl   acl ON acl.source_id = s.id
                          AND acl.principal_id = :principal
                          AND acl.permission = 'read'
WHERE fts_chunks MATCH :fts
  AND s.tenant_id = :tenant
ORDER BY rank
LIMIT :trace_limit
"""


def query_tokens(text: str, limit: int = 12) -> list[str]:
    """Lower-cased alphanumeric tokens from user text, de-duplicated and capped.

    Used by the index-independent scans below. Tokens are alphanumeric by construction, so they
    are safe to use as LIKE operands, and they are still passed as bound parameters.
    """
    out: list[str] = []
    for token in _TOKEN.findall(text or ""):
        low = token.lower()
        if len(low) >= 2 and low not in _STOPWORDS and low not in out:
            out.append(low)
        if len(out) >= limit:
            break
    return out


def token_scan(
    conn: sqlite3.Connection,
    *,
    query: str,
    tenant_id: str | None = None,
    states: Sequence[str] | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Search the ``chunks`` table directly, bypassing the FTS index entirely.

    Why this exists: quarantined chunks are deliberately never written to the FTS index, which is
    correct defence in depth but means an index-based query cannot *see* them. Two features need to
    see them anyway:

    * the admin-only forensic trace, which must be able to say "this withheld chunk matches your
      query, and here is why it was excluded" rather than showing an empty list; and
    * the unguarded measurement baseline, which has to represent what a pipeline *without* a
      write-time firewall would have indexed — namely everything.

    Scoring is a simple count of matched tokens. This is not a ranking function and is not used to
    serve any guarded retrieval; it never returns chunk text to a non-admin caller.
    """
    tokens = query_tokens(query)
    if not tokens:
        return []
    where = " OR ".join(["c.normalized_text LIKE ? ESCAPE '\\'"] * len(tokens))
    params: list[Any] = [f"%{t}%" for t in tokens]
    score_expr = " + ".join(
        ["(CASE WHEN c.normalized_text LIKE ? ESCAPE '\\' THEN 1 ELSE 0 END)"] * len(tokens)
    )
    sql = f"""
    SELECT c.id AS chunk_id, c.text AS raw_text, c.normalized_text AS normalized_text,
           c.state AS chunk_state, c.max_severity AS max_severity, c.risk_score AS risk_score,
           dv.id AS version_id, dv.version AS version,
           d.id AS document_id, d.title AS title, d.status AS document_status,
           s.id AS source_id, s.tenant_id AS tenant_id, s.trust_tier AS trust_tier,
           s.status AS source_status,
           ({score_expr}) AS match_score
    FROM chunks c
    JOIN document_versions dv ON dv.id = c.document_version_id
    JOIN documents         d  ON d.id  = dv.document_id
    JOIN sources           s  ON s.id  = d.source_id
    WHERE ({where})
    """
    score_params = [f"%{t}%" for t in tokens]
    bound: list[Any] = [*score_params, *params]
    if tenant_id is not None:
        sql += " AND s.tenant_id = ?"
        bound.append(tenant_id)
    if states:
        sql += f" AND c.state IN ({','.join('?' * len(states))})"
        bound.extend(states)
    sql += " ORDER BY match_score DESC, c.created_at DESC LIMIT ?"
    bound.append(limit)
    return [dict(r) for r in conn.execute(sql, tuple(bound)).fetchall()]


def build_fts_query(text: str) -> str:
    """Turn arbitrary user text into a safe FTS5 ``MATCH`` expression.

    User input is never interpolated into FTS5 query syntax. Every alphanumeric token is extracted
    and emitted as a quoted phrase joined by ``OR``; quotes inside a token are doubled. That makes
    ``"); DROP TABLE`` and ``NEAR/x`` and an unbalanced quote all harmless, and it means a query
    with no usable token yields an expression that matches nothing rather than everything.
    """
    raw = [t.lower() for t in _TOKEN.findall(text or "") if len(t) >= 2]
    if not raw:
        return ""
    content = [t for t in raw if t not in _STOPWORDS]
    # If the query is nothing but function words, fall back to them rather than matching nothing —
    # an empty expression would be indistinguishable from "the guard withheld everything".
    tokens = content or raw
    seen: list[str] = []
    for t in tokens[:32]:
        if t not in seen:
            seen.append(t)
    return " OR ".join('"' + t.replace('"', '""') + '"' for t in seen)


@dataclass(slots=True)
class RetrievedChunk:
    chunk_id: str
    text: str
    source_id: str
    document_id: str
    version: int
    citation: str
    trust_tier: str
    score: float
    risk_tags: list[str] = field(default_factory=list)
    max_severity: str = "none"
    risk_score: float = 0.0
    title: str | None = None
    uri: str | None = None
    effective_from: str = ""
    raw_span: tuple[int, int] = (0, 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "source_id": self.source_id,
            "document_id": self.document_id,
            "version": self.version,
            "citation": self.citation,
            "trust_tier": self.trust_tier,
            "score": round(self.score, 6),
            "risk_tags": list(self.risk_tags),
            "max_severity": self.max_severity,
            "risk_score": self.risk_score,
            "title": self.title,
            "uri": self.uri,
            "effective_from": self.effective_from,
            "raw_span": list(self.raw_span),
        }


@dataclass(slots=True)
class ExclusionRecord:
    """Why one candidate was dropped. Admin-only; never serialised into a reader's response."""

    chunk_id: str
    source_id: str
    reasons: list[str]
    chunk_state: str | None = None
    version_state: str | None = None
    trust_tier: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "source_id": self.source_id,
            "reasons": list(self.reasons),
            "chunk_state": self.chunk_state,
            "version_state": self.version_state,
            "trust_tier": self.trust_tier,
        }


@dataclass(slots=True)
class RetrievalResult:
    run_id: str
    tenant_id: str
    query: str
    context_chunks: list[RetrievedChunk] = field(default_factory=list)
    filtered_count: int = 0
    candidate_count: int = 0
    policy_revision: str = POLICY_REVISION
    guard_enforced: bool = True
    fail_closed: bool = False
    fail_reason: str | None = None
    identity_source: str = "verified_token"
    as_of_valid: str = ""
    as_of_recorded: str = ""
    latency_ms: float = 0.0
    notes: list[str] = field(default_factory=list)
    integrity_alerts: list[dict[str, Any]] = field(default_factory=list)
    #: Admin-only. Empty for readers and reviewers, always.
    trace: list[ExclusionRecord] | None = None

    def chunk_ids(self) -> list[str]:
        return [c.chunk_id for c in self.context_chunks]

    def texts(self) -> list[str]:
        return [c.text for c in self.context_chunks]

    def as_dict(self, *, include_trace: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "query": self.query,
            "context_chunks": [c.as_dict() for c in self.context_chunks],
            "filtered_count": self.filtered_count,
            "candidate_count": self.candidate_count,
            "policy_revision": self.policy_revision,
            "guard_enforced": self.guard_enforced,
            "fail_closed": self.fail_closed,
            "identity_source": self.identity_source,
            "as_of_valid": self.as_of_valid,
            "as_of_recorded": self.as_of_recorded,
            "latency_ms": round(self.latency_ms, 3),
            "notes": list(self.notes),
            "integrity_alerts": self.integrity_alerts,
        }
        if self.fail_reason:
            payload["fail_reason"] = self.fail_reason
        if include_trace and self.trace is not None:
            payload["trace"] = [e.as_dict() for e in self.trace]
        return payload


def _risk_tags(conn: sqlite3.Connection, chunk_ids: Sequence[str]) -> dict[str, list[str]]:
    if not chunk_ids:
        return {}
    placeholders = ",".join("?" * len(chunk_ids))
    rows = conn.execute(
        "SELECT chunk_id, rule_id, rule_family, severity, mitigated_by FROM risk_findings"
        f" WHERE chunk_id IN ({placeholders})",
        tuple(chunk_ids),
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        tag = f"{r['rule_id']}:{r['rule_family']}:{r['severity']}"
        if r["mitigated_by"]:
            tag += ":mitigated"
        out.setdefault(r["chunk_id"], []).append(tag)
    return out


def _trace_reasons(row: sqlite3.Row, *, min_trust_rank: int, as_of_valid: str) -> list[str]:
    reasons: list[str] = []
    if row["source_status"] != "active":
        reasons.append(f"source_status={row['source_status']}")
    if row["source_expires_at"] and str(row["source_expires_at"]) <= as_of_valid:
        reasons.append("source_expired")
    if row["document_status"] != "active":
        reasons.append(f"document_status={row['document_status']}")
    if row["chunk_state"] != "active":
        reasons.append(f"chunk_state={row['chunk_state']}")
    if row["version_state"] is None:
        reasons.append("no_validity_row_at_as_of_recorded")
    elif row["version_state"] != "active":
        reasons.append(f"version_state={row['version_state']}")
    else:
        if row["effective_from"] and str(row["effective_from"]) > as_of_valid:
            reasons.append("not_yet_effective")
        if row["effective_to"] and str(row["effective_to"]) <= as_of_valid:
            reasons.append("effective_period_ended")
    if row["acl_principal"] is None:
        reasons.append("no_read_acl_for_principal")
    if TRUST_ORDER.get(row["trust_tier"], 0) < min_trust_rank:
        reasons.append(f"below_trust_floor({row['trust_tier']})")
    return reasons


def guarded_search(
    conn: sqlite3.Connection,
    manifests: ManifestStore,
    principal: Principal,
    *,
    query: str,
    run_id: str,
    limit: int = 5,
    as_of_valid: datetime | None = None,
    as_of_recorded: datetime | None = None,
    config: FirewallConfig | None = None,
    include_trace: bool = False,
) -> RetrievalResult:
    """Execute the guarded search. Never raises; on any error it returns a fail-closed result."""
    config = config or FirewallConfig()
    started = time.perf_counter()
    current = now()
    requested_valid = to_utc(as_of_valid) if as_of_valid else current
    clamped_future = False
    if (
        requested_valid > current
        and not principal.is_reviewer
        and not config.readers_may_query_future_valid_time
    ):
        # An independent red-team review observed that an unbounded `as_of_valid` lets a reader
        # surface content whose effective date is in the future — reading a scheduled policy before
        # it takes effect.
        #
        # The honest resolution is NOT to block it by default. Asking "what will the refund window
        # be in December?" is a first-class feature of this product and the release contract's own
        # seed vector MF-SEED-05 requires a *reader* to be able to do exactly that. The real lesson
        # is narrower and is stated plainly in docs/SECURITY.md: **valid time is not an access
        # control.** If content must stay secret until a date, withhold the ACL until that date, or
        # leave it in review until then — do not rely on `effective_from` to hide it.
        #
        # For deployments that schedule confidential policy ahead of publication, this switch
        # closes the window for non-reviewers. Either way, anything returned ahead of its effective
        # date is explicitly tagged below, so a caller can never mistake a scheduled policy for one
        # that is in force today.
        requested_valid = current
        clamped_future = True
    valid_iso = iso(requested_valid)
    recorded_iso = iso(to_utc(as_of_recorded) if as_of_recorded else current)
    now_iso_value = iso(current)
    limit = max(1, min(int(limit), config.max_retrieve_limit))
    min_trust_rank = TRUST_ORDER.get(config.min_retrieval_trust_tier, 0)

    result = RetrievalResult(
        run_id=run_id,
        tenant_id=principal.tenant_id,
        query=query,
        as_of_valid=valid_iso,
        as_of_recorded=recorded_iso,
        guard_enforced=True,
    )
    if clamped_future:
        result.notes.append(
            "as_of_valid was in the future and has been clamped to now, because this deployment "
            "sets readers_may_query_future_valid_time=false. Reading not-yet-effective content "
            "then requires the reviewer role."
        )

    try:
        fts = build_fts_query(query)
        if not fts:
            # No usable search token. Returning nothing is the correct fail-safe: the contract
            # requires failing safe when there is no eligible evidence.
            result.latency_ms = (time.perf_counter() - started) * 1000.0
            result.fail_reason = "query contained no usable search token"
            return result

        params = {
            "fts": fts,
            "principal": principal.id,
            "tenant": principal.tenant_id,
            "as_of_valid": valid_iso,
            "as_of_recorded": recorded_iso,
            # over-fetch so that trust-floor and integrity exclusions cannot silently shrink the
            # page below `limit` when eligible rows exist further down the ranking
            "limit": limit * 4,
        }
        rows = conn.execute(_GUARDED_SQL, params).fetchall()

        # Layer 2: configured trust floor.
        eligible: list[sqlite3.Row] = []
        for row in rows:
            if TRUST_ORDER.get(row["trust_tier"], 0) < min_trust_rank:
                continue
            eligible.append(row)

        # Layer 3: integrity recheck against the side-store manifest.
        verified: list[sqlite3.Row] = []
        for row in eligible:
            key = ManifestStore.chunk_key(row["chunk_id"])
            if manifests.verify(key, row["raw_text"]):
                verified.append(row)
                continue
            expected = manifests.get(key)
            result.integrity_alerts.append(
                {
                    "chunk_id": row["chunk_id"],
                    "source_id": row["source_id"],
                    "document_id": row["document_id"],
                    "reason": "manifest_missing" if expected is None else "digest_mismatch",
                    "detail": (
                        "stored chunk text does not match the expected digest held in the "
                        "side-store manifest; chunk withheld from retrieval"
                    ),
                }
            )

        selected = verified[:limit]
        tags = _risk_tags(conn, [r["chunk_id"] for r in selected])
        for row in selected:
            chunk_tags = list(tags.get(row["chunk_id"], []))
            # An independent review demonstrated that original steering text with no lexical
            # signal lands ACTIVE and is returned with no tags at all — the documented ceiling of a
            # deterministic detector. A consumer cannot act on a limitation it cannot see, so every
            # chunk from a weakly-trusted source now carries a provenance tag whether or not any
            # rule fired. This does not pretend to detect anything; it surfaces where the text came
            # from so a downstream policy can treat it as data rather than instruction.
            if TRUST_ORDER.get(row["trust_tier"], 0) <= TRUST_ORDER["unreviewed_internal"]:
                chunk_tags.append(f"PROVENANCE:{row['trust_tier']}:treat_as_data_not_instructions")
            if str(row["effective_from"]) > now_iso_value:
                # Returned because the caller asked about a future instant. It is a scheduled
                # revision, not the policy in force today, and must never be presented as current.
                chunk_tags.append("NOT_YET_IN_FORCE:scheduled_revision")
                if not any("scheduled revision" in n for n in result.notes):
                    result.notes.append(
                        "This result includes at least one scheduled revision that is not yet in "
                        "force. It is what the policy will be at the requested as-of time, not "
                        "what it is today."
                    )
            result.context_chunks.append(
                RetrievedChunk(
                    chunk_id=row["chunk_id"],
                    text=row["raw_text"],
                    source_id=row["source_id"],
                    document_id=row["document_id"],
                    version=int(row["version"]),
                    citation=f"{row['source_id']}#v{int(row['version'])}",
                    trust_tier=row["trust_tier"],
                    score=float(row["rank"]),
                    risk_tags=chunk_tags,
                    max_severity=row["max_severity"],
                    risk_score=float(row["risk_score"]),
                    title=row["title"],
                    uri=row["uri"],
                    effective_from=str(row["effective_from"]),
                    raw_span=(int(row["raw_start"]), int(row["raw_end"])),
                )
            )

        # Counts shown to a reader describe only what the reader is allowed to know about.
        result.candidate_count = len(verified)
        result.filtered_count = len(result.context_chunks)

        if include_trace and principal.is_admin:
            trace_params = {**params, "trace_limit": max(50, limit * 10)}
            trace_rows = conn.execute(_TRACE_SQL, trace_params).fetchall()
            trace: list[ExclusionRecord] = []
            returned = set(result.chunk_ids())
            seen_in_trace: set[str] = set()
            for row in trace_rows:
                reasons = _trace_reasons(row, min_trust_rank=min_trust_rank, as_of_valid=valid_iso)
                if not reasons and row["chunk_id"] not in returned:
                    key = ManifestStore.chunk_key(row["chunk_id"])
                    if not manifests.verify(key, row["raw_text"]):
                        reasons.append("integrity_digest_mismatch")
                    else:
                        reasons.append("ranked_below_limit")
                if reasons:
                    seen_in_trace.add(row["chunk_id"])
                    trace.append(
                        ExclusionRecord(
                            chunk_id=row["chunk_id"],
                            source_id=row["source_id"],
                            reasons=reasons,
                            chunk_state=row["chunk_state"],
                            version_state=row["version_state"],
                            trust_tier=row["trust_tier"],
                        )
                    )

            # Withheld chunks are never written to the FTS index, so the query above cannot see
            # them. An operator asking "why did my query not return the thing I know is in there"
            # needs exactly those rows, so they are added from an index-independent scan. Still
            # admin-only and still tenant-scoped.
            for row in token_scan(
                conn,
                query=query,
                tenant_id=principal.tenant_id,
                states=("quarantined", "review_required", "rejected", "revoked", "superseded"),
                limit=max(25, limit * 5),
            ):
                if row["chunk_id"] in seen_in_trace or row["chunk_id"] in returned:
                    continue
                seen_in_trace.add(row["chunk_id"])
                trace.append(
                    ExclusionRecord(
                        chunk_id=row["chunk_id"],
                        source_id=row["source_id"],
                        reasons=[
                            f"chunk_state={row['chunk_state']}",
                            "not_present_in_search_index",
                        ],
                        chunk_state=row["chunk_state"],
                        version_state=None,
                        trust_tier=row["trust_tier"],
                    )
                )
            trace.sort(key=lambda e: (e.chunk_state or "", e.chunk_id))
            result.trace = trace

    except Exception as exc:
        result.context_chunks = []
        result.filtered_count = 0
        result.candidate_count = 0
        result.fail_closed = True
        result.guard_enforced = True
        result.trace = None
        result.fail_reason = f"{type(exc).__name__}: guard could not prove eligibility"

    result.latency_ms = (time.perf_counter() - started) * 1000.0
    return result


def unguarded_search_for_baseline(
    conn: sqlite3.Connection,
    *,
    query: str,
    tenant_id: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """A naive, **deliberately unprotected** lexical search used only as a measurement baseline.

    It scans the ``chunks`` table directly rather than the FTS index, and that choice is the honest
    one: a pipeline with no write-time firewall would have indexed every chunk, including the ones
    this system quarantined. Searching only the guarded index would quietly give the baseline the
    benefit of the very gate it is supposed to be a baseline *for*, and would make the side-by-side
    comparison look like a tie when it is not.

    This never serves a retrieval request. The API exposes it only behind
    ``MF_ENABLE_UNGUARDED_BASELINE`` plus an admin role, and every response carrying its output is
    labelled as a baseline.
    """
    rows = token_scan(conn, query=query, tenant_id=tenant_id, states=None, limit=limit * 4)
    out: list[dict[str, Any]] = []
    for row in rows[:limit]:
        out.append(
            {
                "chunk_id": row["chunk_id"],
                "raw_text": row["raw_text"],
                "source_id": row["source_id"],
                "tenant_id": row["tenant_id"],
                "version": row["version"],
                "chunk_state": row["chunk_state"],
                "trust_tier": row["trust_tier"],
                "max_severity": row["max_severity"],
                "rank": -float(row["match_score"]),
                "would_have_been_indexed_without_a_write_gate": True,
            }
        )
    return out
