-- Memory Firewall — persistence schema.
-- SQLite, WAL journal, FTS5 external index with manual synchronisation.
-- Owned by the coordinator role (docs/IMPLEMENTATION_PLAN.md §2). Single source of truth.
--
-- Bitemporality: content identity lives in `document_versions`; the *state over time* of a version
-- lives in `version_validity`, which carries BOTH valid time (effective_from/effective_to) and
-- system/transaction time (system_recorded_from/system_recorded_to). A state change never mutates a
-- validity row: it closes the current row's system time and inserts a new one. An as-of query is
-- therefore truthful about what was believed at a past instant as well as what was in force.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Role is the authority boundary. `token_sha256` is the only accepted proof of identity; the
-- plaintext token is never stored. Trust decisions read this table, never request bodies.
CREATE TABLE IF NOT EXISTS principals (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('reader', 'reviewer', 'admin')),
    token_sha256 TEXT UNIQUE,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_principals_tenant ON principals(tenant_id);

-- Trust tier is administrative state. Nothing in ingested content can write to this column; the
-- ingest path never passes a caller-supplied tier (see policy/engine tests).
CREATE TABLE IF NOT EXISTS sources (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_type TEXT NOT NULL DEFAULT 'manual',
    owner          TEXT,
    trust_tier     TEXT NOT NULL CHECK (trust_tier IN (
                       'authoritative_signed', 'authoritative_reviewed', 'reviewed_internal',
                       'unreviewed_internal', 'external_untrusted')),
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    revoked_reason TEXT,
    expires_at     TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    set_by         TEXT REFERENCES principals(id)
);
CREATE INDEX IF NOT EXISTS idx_sources_tenant ON sources(tenant_id, status);

CREATE TABLE IF NOT EXISTS source_acl (
    source_id    TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    permission   TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    granted_at   TEXT NOT NULL,
    granted_by   TEXT REFERENCES principals(id),
    PRIMARY KEY (source_id, principal_id, permission)
);

CREATE TABLE IF NOT EXISTS documents (
    id         TEXT PRIMARY KEY,
    source_id  TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    uri        TEXT,
    title      TEXT,
    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'tombstoned')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source_id, status);

CREATE TABLE IF NOT EXISTS document_versions (
    id                  TEXT PRIMARY KEY,
    document_id         TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version             INTEGER NOT NULL,
    content_sha256      TEXT NOT NULL,
    raw_text            TEXT NOT NULL,
    normalized_text     TEXT NOT NULL,
    normalization_report TEXT NOT NULL DEFAULT '{}',
    detector_version    TEXT NOT NULL,
    actor_principal_id  TEXT REFERENCES principals(id),
    parent_version_id   TEXT REFERENCES document_versions(id),
    created_at          TEXT NOT NULL,
    UNIQUE (document_id, version)
);
CREATE INDEX IF NOT EXISTS idx_versions_document ON document_versions(document_id, version);

-- One row per (version, state) interval. Append-only: see header note.
CREATE TABLE IF NOT EXISTS version_validity (
    id                   TEXT PRIMARY KEY,
    document_version_id  TEXT NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,
    state                TEXT NOT NULL CHECK (state IN (
                             'active', 'review_required', 'quarantined', 'rejected',
                             'revoked', 'superseded')),
    effective_from       TEXT NOT NULL,
    effective_to         TEXT,
    system_recorded_from TEXT NOT NULL,
    system_recorded_to   TEXT,
    actor_principal_id   TEXT REFERENCES principals(id),
    reason               TEXT,
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validity_version ON version_validity(document_version_id);
CREATE INDEX IF NOT EXISTS idx_validity_open ON version_validity(system_recorded_to, state);

CREATE TABLE IF NOT EXISTS chunks (
    id                  TEXT PRIMARY KEY,
    document_version_id TEXT NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,
    ordinal             INTEGER NOT NULL,
    raw_start           INTEGER NOT NULL,
    raw_end             INTEGER NOT NULL,
    text                TEXT NOT NULL,
    normalized_text     TEXT NOT NULL,
    text_sha256         TEXT NOT NULL,
    state               TEXT NOT NULL CHECK (state IN (
                            'active', 'review_required', 'quarantined', 'rejected',
                            'revoked', 'superseded')),
    risk_score          REAL NOT NULL DEFAULT 0.0,
    max_severity        TEXT NOT NULL DEFAULT 'none',
    created_at          TEXT NOT NULL,
    UNIQUE (document_version_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_chunks_version ON chunks(document_version_id, state);
CREATE INDEX IF NOT EXISTS idx_chunks_state ON chunks(state);

-- Lexical index. Manually synchronised with `chunks` inside the same transaction as the write that
-- changes a chunk's state. `chunk_id` is UNINDEXED so it is storage only, not a search term.
CREATE VIRTUAL TABLE IF NOT EXISTS fts_chunks USING fts5(
    text,
    chunk_id UNINDEXED,
    tokenize = 'porter unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS risk_findings (
    id                   TEXT PRIMARY KEY,
    chunk_id             TEXT REFERENCES chunks(id) ON DELETE CASCADE,
    document_version_id  TEXT NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,
    rule_id              TEXT NOT NULL,
    rule_family          TEXT NOT NULL,
    severity             TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence           REAL NOT NULL,
    confidence_semantics TEXT NOT NULL,
    evidence_start       INTEGER NOT NULL,
    evidence_end         INTEGER NOT NULL,
    evidence_text        TEXT NOT NULL,
    evidence_space       TEXT NOT NULL CHECK (evidence_space IN ('raw', 'normalized')),
    normalization_applied TEXT NOT NULL DEFAULT '',
    mitigated_by         TEXT,
    detector_version     TEXT NOT NULL,
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_chunk ON risk_findings(chunk_id);
CREATE INDEX IF NOT EXISTS idx_findings_version ON risk_findings(document_version_id);

-- Typed, narrow claim domain only (blueprint §4.2). Deliberately NOT general fact extraction.
CREATE TABLE IF NOT EXISTS claims (
    id                   TEXT PRIMARY KEY,
    document_version_id  TEXT NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,
    chunk_id             TEXT REFERENCES chunks(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id            TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    subject              TEXT NOT NULL,
    attribute            TEXT NOT NULL,
    region               TEXT NOT NULL DEFAULT 'global',
    customer_tier        TEXT NOT NULL DEFAULT 'standard',
    value_number         REAL,
    value_text           TEXT,
    unit                 TEXT,
    authority_tier       TEXT NOT NULL,
    effective_from       TEXT NOT NULL,
    effective_to         TEXT,
    system_recorded_from TEXT NOT NULL,
    system_recorded_to   TEXT,
    evidence_start       INTEGER NOT NULL DEFAULT 0,
    evidence_end         INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claims_key
    ON claims(tenant_id, subject, attribute, region, customer_tier);

CREATE TABLE IF NOT EXISTS conflicts (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    claim_a_id   TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    claim_b_id   TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN (
                     'needs_review', 'resolved_supersede', 'resolved_dismissed',
                     'resolved_rejected')),
    detected_at  TEXT NOT NULL,
    resolved_at  TEXT,
    resolver_id  TEXT REFERENCES principals(id),
    reason       TEXT,
    UNIQUE (claim_a_id, claim_b_id)
);
CREATE INDEX IF NOT EXISTS idx_conflicts_tenant ON conflicts(tenant_id, status);

CREATE TABLE IF NOT EXISTS review_decisions (
    id                   TEXT PRIMARY KEY,
    target_type          TEXT NOT NULL CHECK (target_type IN ('chunk', 'version', 'conflict')),
    target_id            TEXT NOT NULL,
    decision             TEXT NOT NULL CHECK (decision IN ('approve', 'reject', 'revise')),
    reviewer_principal_id TEXT NOT NULL REFERENCES principals(id),
    reason               TEXT NOT NULL,
    prev_state           TEXT,
    new_state            TEXT,
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reviews_target ON review_decisions(target_type, target_id);

-- Every guarded retrieval writes one row. `excluded` holds (chunk_id, reason) pairs and is only
-- ever served to an admin of the same tenant.
CREATE TABLE IF NOT EXISTS retrieval_exposures (
    id                 TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    principal_id       TEXT NOT NULL,
    query              TEXT NOT NULL,
    as_of_valid        TEXT NOT NULL,
    as_of_recorded     TEXT NOT NULL,
    candidate_count    INTEGER NOT NULL,
    eligible_chunk_ids TEXT NOT NULL,
    excluded           TEXT NOT NULL,
    returned_chunk_ids TEXT NOT NULL,
    guard_enforced     INTEGER NOT NULL DEFAULT 1,
    fail_closed        INTEGER NOT NULL DEFAULT 0,
    latency_ms         REAL NOT NULL,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exposures_tenant ON retrieval_exposures(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS snapshots (
    id             TEXT PRIMARY KEY,
    label          TEXT NOT NULL,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by     TEXT NOT NULL REFERENCES principals(id),
    as_of_valid    TEXT NOT NULL,
    as_of_recorded TEXT NOT NULL,
    note           TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id                 TEXT PRIMARY KEY,
    actor_principal_id TEXT,
    tenant_id          TEXT,
    action             TEXT NOT NULL,
    target_type        TEXT,
    target_id          TEXT,
    detail             TEXT NOT NULL DEFAULT '{}',
    parent_version_id  TEXT,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(target_type, target_id);
