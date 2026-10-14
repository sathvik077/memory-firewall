/** Shapes returned by the Memory Firewall API. Kept hand-written and narrow on purpose: this is
 *  a security tool's own UI, so the type surface is the contract we actually rely on rather than a
 *  generated mirror of every field. */

export type TrustTier =
  | "authoritative_signed"
  | "authoritative_reviewed"
  | "reviewed_internal"
  | "unreviewed_internal"
  | "external_untrusted";

export type ChunkState =
  | "active"
  | "review_required"
  | "quarantined"
  | "rejected"
  | "revoked"
  | "superseded";

export type Decision =
  | "ALLOW"
  | "ALLOW_WITH_FLAGS"
  | "REVIEW_REQUIRED"
  | "QUARANTINE"
  | "REJECT";

export interface Health {
  status: "ok" | "degraded";
  schema_version: string | null;
  detector_version: string;
  policy_revision: string;
  fts5: boolean;
  database: string;
  guard_enforced: boolean;
  unguarded_baseline_enabled: boolean;
  notes: string[];
}

export interface WhoAmI {
  principal: string;
  tenant_id: string;
  role: "reader" | "reviewer" | "admin";
  identity_source: "verified_token";
}

export interface Finding {
  rule_id: string;
  rule_family: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  confidence_semantics: string;
  evidence_start: number;
  evidence_end: number;
  evidence_text: string;
  normalization_applied: string;
  mitigated_by: string | null;
  detector_version: string;
  chunk_id?: string;
}

export interface ChunkOutcome {
  chunk_id: string;
  ordinal: number;
  decision: Decision;
  state: ChunkState;
  reasons: string[];
  risk_score: number;
  max_severity: string;
  rule_ids: string[];
  raw_span: [number, number];
  preview: string;
}

export interface IngestResult {
  document_id: string;
  version_id: string;
  version: number;
  source_id: string;
  content_sha256: string;
  state: string;
  decision: Decision;
  chunks: ChunkOutcome[];
  findings: Finding[];
  claims: Array<Record<string, unknown>>;
  conflicts: Array<Record<string, unknown>>;
  normalization_report: Record<string, unknown>;
  ignored_privileged_fields: string[];
  effective_from: string;
  active_chunk_ids: string[];
  withheld_chunk_ids: string[];
}

export interface RetrievedChunk {
  chunk_id: string;
  text: string;
  source_id: string;
  document_id: string;
  version: number;
  citation: string;
  trust_tier: TrustTier;
  score: number;
  risk_tags: string[];
  max_severity: string;
  risk_score: number;
  title: string | null;
  effective_from: string;
}

export interface TraceEntry {
  chunk_id: string;
  source_id: string;
  reasons: string[];
  chunk_state: string | null;
  version_state: string | null;
  trust_tier: string | null;
}

export interface RetrievalResult {
  run_id: string;
  tenant_id: string;
  query: string;
  context_chunks: RetrievedChunk[];
  filtered_count: number;
  candidate_count: number;
  policy_revision: string;
  guard_enforced: boolean;
  fail_closed: boolean;
  fail_reason?: string;
  identity_source: string;
  as_of_valid: string;
  as_of_recorded: string;
  latency_ms: number;
  notes?: string[];
  integrity_alerts: Array<Record<string, string>>;
  trace?: TraceEntry[];
  ignored_privileged_fields?: string[];
}

export interface SourceRow {
  id: string;
  tenant_id: string;
  connector_type: string;
  owner: string | null;
  trust_tier: TrustTier;
  status: "active" | "revoked";
  revoked_reason: string | null;
  expires_at: string | null;
  documents: number;
  read_acl: string[];
}

export interface QuarantineItem {
  chunk_id: string;
  state: ChunkState;
  text: string;
  risk_score: number;
  max_severity: string;
  raw_start: number;
  raw_end: number;
  version_id: string;
  version: number;
  document_id: string;
  title: string | null;
  source_id: string;
  trust_tier: TrustTier;
  findings: Finding[];
  preview_html: string;
  preview_text: string;
}

export interface ValidityRow {
  state: ChunkState;
  effective_from: string;
  effective_to: string | null;
  system_recorded_from: string;
  system_recorded_to: string | null;
  reason: string | null;
}

export interface LedgerRow {
  version_id: string;
  version: number;
  content_sha256: string;
  created_at: string;
  parent_version_id: string | null;
  document_id: string;
  title: string | null;
  document_status: string;
  source_id: string;
  trust_tier: TrustTier;
  source_status: string;
  validity: ValidityRow[];
  chunk_states: Record<string, number>;
}

export interface ConflictRow {
  id: string;
  kind: string;
  status: string;
  detected_at: string;
  reason: string | null;
  region: string;
  customer_tier: string;
  incoming_value: number | null;
  incoming_authority: TrustTier;
  incoming_source: string;
  existing_value: number | null;
  existing_authority: TrustTier;
  existing_source: string;
}

export interface ExposureRow {
  run_id: string;
  principal_id: string;
  query: string;
  as_of_valid: string;
  as_of_recorded: string;
  candidate_count: number;
  returned_chunk_ids: string[];
  excluded: TraceEntry[] | string;
  guard_enforced: number;
  fail_closed: number;
  latency_ms: number;
  created_at: string;
}

export interface SnapshotRow {
  id: string;
  label: string;
  as_of_valid: string;
  as_of_recorded: string;
  note: string;
  created_at: string;
}

export interface ReplayResult {
  snapshot_id: string;
  label: string;
  historical_view: boolean;
  view_label: string;
  as_of_valid: string;
  as_of_recorded: string;
  coordinates: { historical: Record<string, string>; current: Record<string, string> };
  query: string;
  historical: RetrievalResult;
  current: RetrievalResult;
  diff: {
    only_in_historical: string[];
    only_in_current: string[];
    unchanged: string[];
    answer_context_changed: boolean;
    historical_citations: string[];
    current_citations: string[];
    revisions_changed: string[];
  };
}

export interface ScenarioCheck {
  name: string;
  expected: unknown;
  observed: unknown;
  passed: boolean;
}

export interface ScenarioMeta {
  id: string;
  name: string;
  kind: "attack" | "benign" | "control";
  contract_ref: string;
  description: string;
  expectation: string;
}

export interface ScenarioResult extends ScenarioMeta {
  passed: boolean;
  checks: ScenarioCheck[];
  steps: string[];
  evidence: Record<string, unknown>;
  caveat: string | null;
  isolated: boolean;
}

export interface Stats {
  tenant_id: string;
  sources: number;
  documents: number;
  chunk_states: Record<string, number>;
  active_chunks: number;
  withheld_chunks: number;
  open_conflicts: number;
  retrievals: number;
  snapshots: number;
  manifest_entries: number;
  detector_version: string;
  policy_revision: string;
}

export interface ContextPack {
  run_id: string;
  query: string;
  chunks: Array<{
    chunk_id: string;
    text: string;
    citation: string;
    source_id: string;
    version: number;
    trust_tier: TrustTier;
    risk_tags: string[];
  }>;
  citations: string[];
  insufficient_evidence: boolean;
  policy_decision: string;
  answer: string | null;
  answer_basis: Array<Record<string, unknown>>;
  notes: string[];
}

export interface UnguardedComparison {
  query: string;
  unguarded_baseline: {
    baseline: string;
    is_memory_firewall_output: boolean;
    warning: string;
    hits: Array<{ chunk_id: string; raw_text: string; source_id: string; chunk_state: string }>;
  };
  guarded_result: RetrievalResult;
  comparison: {
    unguarded_hit_count: number;
    guarded_hit_count: number;
    chunks_withheld_by_guard: string[];
  };
  labels: Record<string, string>;
}
