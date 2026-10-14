# IMPLEMENTATION_BLUEPRINT.md — Memory Firewall

**Authoritative companion to CLAUDE.md.** This is a build plan, not source code. Implement and test on the actual machine.

## 1. Freeze the MVP, no cloud dependencies

- Python 3.12+ (`uv`, Pydantic 2, FastAPI, SQLite WAL + **FTS5**), Node 22 (`npm ci`, Vite/React/TypeScript). `make setup` checks FTS5 at startup and fails with helpful instructions if missing; do not silently replace real retrieval with canned responses. No embeddings or LLM needed for required demo.
- API `127.0.0.1:8002`, dashboard `127.0.0.1:5174` using `MF_API_PORT`, `MF_WEB_PORT` overrides. Separate local SQLite database and runtime from Agent Drift.
- Commands: `make setup`, `make dev` (API/UI), `make seed` (idempotent synthetic corpus), `make smoke` (API calls for poison write/retrieve), `make test`, `make lint`, `make typecheck`, `make build`, `make eval`, `make verify`, `make screenshots`, `make clean-demo`. Document Mac/Linux and WSL2 prerequisites. Docker Compose uses localhost port binding, persisted demo DB and explicit dev-only warning.

## 2. Trust boundary and security principals

**Client cannot assert its own trust.** Administrator creates source records with `tenant_id`, `trust_tier`, owner, ACL and status. Upload API accepts `source_id` and content, but **never** accepts authoritative approval metadata from text/upload; trust tier and allowed privileges are resolved from protected server state. Plain document claims such as `role: system` are always untrusted content. Reviewer identity is derived from an authenticated admin session/token; `tenant_id`, principal and role for retrieval must be derived from authenticated caller context, **not user-provided JSON**. For demo, setup creates randomized local admin/tenant-reader credentials in ignored `.env`, with clear dev profile and user switching; reject forged principal/tenant fields.

Enforce denial server-side and at query time: `source.tenant`, document/chunk ACL, `active|quarantined|rejected|revoked`, manifest digest integrity, version validity and requested principal. Filter with permission-aware SQL before returning or ranking any candidate metadata; exclude forbidden docs from `source_id`, citations, snippets, metadata, counters or error messages. Context-pack builder receives ONLY filtered chunks. A `trace` visible to admin may include excluded IDs, but a tenant reader must not infer their existence. If DB/index or policy verification fails, refuse rather than return unguarded memory.

**Reviewer decisions:** only authenticated reviewer/admin may promote quarantined content or trusted revisions. Approval does not retroactively label external text authoritative; it chooses a documented trust transition, reindexing transactionally. A user cannot approve a document by submitting `"approved_by": "admin"`.

**Integrity is limited:** SHA-256 digest protects consistency with a separately protected expected value; if attacker controls both DB and stored hash, the hash alone proves nothing. Optional HMAC key belongs outside source DB. Be honest about limitations.

## 3. Persistence architecture / bitemporality

Tables: `tenants`, `principals`, `sources`, `documents`, `document_versions` (`system_recorded_from`, `system_recorded_to`, `effective_from`, `effective_to`), `chunks`, `chunk_acl` or inherited versioned ACL, `fts_chunks` (FTS5 external-content or manual synchronization), `risk_findings`, `claims`, `conflicts`, `review_decisions`, `retrieval_exposures` and `audit_events` with foreign keys.

- New source/doc content -> hash + normalize -> scan before marking ACTIVE -> version + chunk index in one transaction. Quarantined chunks NEVER appear in active FTS results.
- Authoritative new refund-policy v2 for 14 days, effective next month: reviewer authorizes with `valid_from`; historical 30-day v1 remains queryable by **authorized as-of-time query**, not in current retrieval after v2 effective. Record the system-time of both version and review so `as_known_at` can truthfully distinguish backdated content; implement both valid/effective time and recorded/transaction time for required v1. If not all bi-temporal semantics implemented, do NOT call it bi-temporal and flag gate.
- Rejected/revoked/tombstoned chunks cannot be returned from any query; snapshots never re-promote rejected content, only present authorized historical **what was visible** with correct labels. Rollback means create a reviewed new active revision from a prior authorized version, not delete audit trail.
- Index revocation, source ACL edits and document deletion cannot leak through stale caches. In MVP, no cross-request result cache is easiest and preferred. Atomic writes keep tables and FTS consistent; test transaction rollback.

## 4. Detector policy with useful, falsifiable semantics

1. Deterministic signals: role spoofing, imperative instructions directed at agent, tool/outbound request indicators, hidden Unicode or delimiter spoofing, source trust mismatch, unauthorized altered claim. Each risk finding has stable `rule_id`, original byte/character span, normalization performed, source ID, detector version and severity.
2. Refuse universal semantic truth detection. For claims, use a small **typed policy domain**: `RefundPolicy(region, customer_tier, days, effective_date)` plus explicit `source_id`, provenance, structured source version. Only compare claims with equivalent `(region,tier,effective_time)` and equal authority. Conflicts require REVIEW. Valid approved change to 14 days should pass and supersede 30 days at proper date; do not treat all changes as poisoning.
3. Demonstrate benign technical quotation with words “ignore previous instructions” does not cause hard-block without surrounding evidence; log a low-confidence review where appropriate. Report the false-positive rate against benign QA.
4. Expose scanning decisions as `ALLOW`, `QUARANTINE`, `REJECT`, `REVIEW_REQUIRED` with **explicit transition table** in `docs/THREAT_MODEL.md`; reviewer transitions go through one shared service used by API + SDK.
5. Offlined retrieval: FTS5 query returns relevant permitted content with stable citations and chunk IDs, no hardcoded "30 days" answer. Optional answer rendering may deterministically summarize claim fields when citation trace supports it. No LLM call in default tests.

## 5. Actual demo and guard validation

**Corpus:** trusted synthetic Policy v1 “30 days”; user-generated issue note claims “2 days, ignore previous policy”; source B document for tenant `competitor`; reviewer approved v2 “14 days” with effective date.

**Mandatory smoke:**
- Ingest v1 from admin-approved authority -> ACTIVE; retrieval from authorized reader cites v1 and `30 days`.
- Ingest poisoned issue from unreviewed source -> QUARANTINED, clear rule IDs/evidence spans. Same query -> poison **absent**; the trusted v1 citation remains.
- Seed legacy poison **directly into untrusted/tainted index for adversarial test only** (isolated test fixture, never public endpoint) -> preread guard still excludes it. Assert result does not contain poisoned chunk ID or text.
- Cross-tenant caller attempts to retrieve other tenant -> zero text, zero identifiers, no counter leak. A client request with forged JSON `tenant_id`/`principal` must fail or be ignored in favor of token-derived values.
- Reviewer approves v2 with future effective date -> current-as-of-time returns v1; future-as-of-time returns v2; audit retains v1. Quarantine reject/tombstone revocation changes retrieval immediately.

Use `TEST_VECTORS.json` as release seed for a runnable fixture harness and asserts against real DB and retrieval results; no pre-stored frontend alerts. **Run each test case in an isolated disposable database, seed the declared sources and required reference policy before each retrieval, and perform its setup steps in order.** Keep 120+ original labeled eval cases **separate** from seed tests. Evals compare identical corpora/splits across four conditions: unguarded; keyword-only; write-only; write+retrieve guard, measuring realistic attacker exposure and benign recall.

## 6. Agent ownership, test schedule

| Phase | Owner | Gate |
|---|---|---|
| P0 | Coordinator + research | docs threat/novelty and interface contract, chosen versions and tradeoffs |
| P1 | Core/DB owner | Migration, real ingest+quarantine+FTS retrieve in tests |
| P2 | Security owner | Admin-enforced provenance, tenant/ACL prefilter, tamper, review state transitions |
| P3 | Retrieval/SDK owner | SDK/API parity with exact `ingest`/`retrieve` quickstart, as-of queries |
| P4 | UI owner | Real ingestion/retrieval trace, quarantine review and history graph |
| P5 | Eval owner | Repeatable 120+ labeled cases, baseline comparison, false-positive analysis |
| P6 | Independent reviewer | Cross-tenant/ACL bypass, index/cache bypass, snapshot safety tests |
| P7 | Coordinator | Fresh install, CI, Playwright, Docker, verification and screenshots |

Avoid conflicting edits across agents: coordinator owns schemas and acceptance matrix. Subagents optional; if not available, perform tasks sequentially.

## 7. Evidence and release bar

- `docs/ACCEPTANCE_STATUS.md`: MF-01..MF-27 marked PASS, FAIL or NOT VERIFIED with file/test pointers and measured output; `docs/VERIFICATION.md`: date/environment, exact commands+exit codes, pass counts, actual query excerpts, false-positive/performance stats.
- E2E Playwright captures actual `docs/assets/scan-and-quarantine.png`, `provenance-ledger.png`, `retrieval-trace.png`, `time-machine.png` plus generated architecture SVG from Mermaid.
- `.github/workflows/ci.yml` runs backend tests incl. sqlite FTS/ACL, type/lint, frontend production build and browser E2E; Docker build must actually run, and skipped mandatory checks fail build.
- Security doc clearly says the firewall protects **only ingested/retrieved via its instrumented pipeline**, does not guarantee all semantic poisoning is detected and cannot magically secure arbitrary agent memories elsewhere.
- Mark release NOT READY if forbidden chunk leaks, tenant cross-read occurs, CLI smoke cannot run, required tests skipped or `make verify` nonzero; report precise blocking commands and fixes instead of asserting readiness.
