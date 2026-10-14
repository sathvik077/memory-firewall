# IMPLEMENTATION_PLAN.md — Memory Firewall

**Status:** living document. Created 2026-10-14 before any application code was written, per
`CLAUDE.md` §0.2 and `CLAUDE_LAUNCH_PROMPT.txt`.

**Repo:** `memory-firewall/` (independent sibling of `memory-firewall-build-brief/`).
**Normative contract:** `CLAUDE.md`, `IMPLEMENTATION_BLUEPRINT.md`, `TEST_VECTORS.json`,
`ACCEPTANCE_EVIDENCE_MATRIX.md` — all copied into this repo root and treated as read-only input.

---

## 1. Build order (thin vertical slice first)

| Stage | Outcome | Exit condition |
|---|---|---|
| S0 | Plan, pinned versions, interface contract, research + threat model | this file + `docs/RESEARCH.md` + `docs/THREAT_MODEL.md` exist |
| S1 | **Vertical slice**: one trusted doc ingested ACTIVE, one poisoned doc QUARANTINED, FTS5 retrieval returns only the trusted chunk | `tests/integration/test_vertical_slice.py` green against a real on-disk SQLite file |
| S2 | Real engine: bitemporal versions, ACL/tenant prefilter, tombstones, integrity manifests, review transitions, typed claims | `tests/unit`, `tests/integration` green |
| S3 | Seed-vector harness over `TEST_VECTORS.json`, 12/12 cases, each in a disposable DB | `tests/integration/test_release_vectors.py` green |
| S4 | API + SDK + directory adapter + support-copilot example | `make smoke` green |
| S5 | Dashboard (8 panes) wired to the real API | `make build` green, panes render live data |
| S6 | Eval harness: 178-case dataset × 4 conditions, metrics | `make eval` writes `evals/results/RESULTS.{json,md}` |
| S7 | Playwright E2E + real screenshots, Docker, CI | `make verify` exit 0; `docs/assets/*.png` captured from the running app |
| S8 | Independent red-team review, `ACCEPTANCE_STATUS.md`, `VERIFICATION.md` | every MF gate has PASS / FAIL / NOT VERIFIED with a command and observed output |

**Rule:** S1 must be executable before any frontend work begins. No stage is marked done on the
strength of code existing; it is done when a named command exits 0 and its output is recorded.

---

## 2. Role / file ownership

Subagents are used where the work is genuinely independent; otherwise the coordinator performs the
role sequentially. Ownership is exclusive to avoid conflicting edits — the coordinator alone owns
`schema.sql`, the gate list and the acceptance matrix.

| Phase | Role | Owned paths | Executed by |
|---|---|---|---|
| P0 | Research / threat modelling | `docs/RESEARCH.md` | **independent subagent** (completed 2026-10-14; 12 primary sources fetched and verified) |
| P0 | Coordinator: schema + interfaces | `packages/memory_firewall/memory_firewall/schema.sql`, `docs/DECISIONS.md`, this file | coordinator |
| P1 | Core / DB | `db.py`, `ids.py`, `clock.py`, `chunking.py`, `normalize.py`, `integrity.py`, `audit.py` | coordinator |
| P2 | Security engine | `detector.py`, `claims.py`, `policy.py`, `review.py`, `identity.py` | coordinator |
| P3 | Retrieval / SDK | `retrieval.py`, `contextpack.py`, `snapshots.py`, `engine.py`, `sdk.py`, `adapters/` | coordinator |
| P4 | API | `apps/api/app/**` | coordinator |
| P5 | UI | `apps/dashboard/**` | coordinator |
| P6 | Eval dataset (independent, detector-blind) | `evals/dataset/**` | **independent subagent** (completed 2026-10-14; 178 cases) |
| P6 | Eval harness + metrics | `evals/runner.py`, `evals/conditions.py`, `evals/metrics.py` | coordinator |
| P7 | Independent review / red team | `docs/RED_TEAM_REVIEW.md`, `tests/security/test_redteam_*.py` | **independent subagent**, run after S7 |
| P7 | Release verification | `docs/ACCEPTANCE_STATUS.md`, `docs/VERIFICATION.md` | coordinator |

The P6 dataset author was deliberately kept blind to the detector implementation so that measured
recall is not an artefact of writing the dataset against the rules. See `evals/dataset/DATASET.md`.

---

## 3. Architecture interfaces (frozen before coding)

Three enforcement points, one shared engine. The API and the SDK are both thin shells over
`MemoryFirewallEngine`; there is exactly one implementation of every security decision.

```
                          ┌──────────────────────────────┐
  HTTP (apps/api) ───────▶│                              │
                          │   MemoryFirewallEngine       │
  Python SDK (sdk.py) ───▶│   (single policy authority)   │
                          └──────────────┬───────────────┘
                                         │
  ingest()  ──▶ normalize ──▶ chunk ──▶ detect ──▶ claims ──▶ policy.decide ──▶ one SQL txn
  retrieve()──▶ identity.resolve ──▶ retrieval.guarded_search (permission-aware SQL)
                                    ──▶ integrity recheck ──▶ exposure log ──▶ context pack
  review()  ──▶ review.transition (single shared state machine, audited, transactional)
```

### 3.1 Core engine signatures

```python
# packages/memory_firewall/memory_firewall/engine.py
class MemoryFirewallEngine:
    def __init__(self, db_path: str | Path, *, config: FirewallConfig | None = None) -> None: ...

    # administration (requires an authenticated admin principal)
    def create_tenant(self, actor: Principal, tenant_id: str, name: str) -> Tenant: ...
    def create_principal(
        self,
        actor: Principal,
        principal_id: str,
        tenant_id: str,
        role: Role,
        token: str | None = None,
    ) -> tuple[Principal, str]: ...
    def create_source(
        self,
        actor: Principal,
        source_id: str,
        tenant_id: str,
        trust_tier: TrustTier,
        read_acl: Sequence[str],
        connector_type: str = "manual",
        owner: str | None = None,
    ) -> Source: ...
    def revoke_source(self, actor: Principal, source_id: str, reason: str) -> Source: ...

    # pre-write enforcement point
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
    ) -> IngestResult: ...

    # pre-retrieval enforcement point
    def retrieve(
        self,
        actor: Principal,
        *,
        query: str,
        limit: int = 5,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
        include_trace: bool = False,
    ) -> RetrievalResult: ...

    # at-use enforcement point
    def build_context_pack(
        self, actor: Principal, *, query: str, limit: int = 5, **as_of: datetime | None
    ) -> ContextPack: ...

    # reviewer workflow (one shared transition service for API + SDK)
    def review(
        self,
        actor: Principal,
        *,
        target_type: Literal["chunk", "version"],
        target_id: str,
        decision: Literal["approve", "reject", "revise"],
        reason: str,
        effective_from: datetime | None = None,
        revised_text: str | None = None,
    ) -> ReviewOutcome: ...

    def snapshot(self, actor: Principal, label: str, note: str = "") -> Snapshot: ...
    def replay_snapshot(
        self, actor: Principal, snapshot_id: str, query: str
    ) -> RetrievalResult: ...
```

### 3.2 Decision vocabulary (pre-write)

`ALLOW` · `ALLOW_WITH_FLAGS` · `REVIEW_REQUIRED` · `QUARANTINE` · `REJECT`

Mapped to persisted chunk/version state `active | review_required | quarantined | rejected |
revoked | superseded`. Only `active` is retrievable. The full transition table lives in
`docs/THREAT_MODEL.md` and is asserted by `tests/unit/test_policy_transitions.py`.

`ALLOW_WITH_FLAGS` exists so that a benign document that merely *quotes* an attack string is
retrievable but visibly flagged, instead of being hard-blocked (`CLAUDE.md` Scenario F, MF-SEED-06).
That choice is measured, not asserted: the benign false-positive rate is reported by `make eval`.

### 3.3 Identity contract (non-negotiable)

Tenant, principal and role are resolved **server-side** from a bearer token
(`sha256(token)` looked up in `principals`). Any `tenant_id`, `principal`, `trust_tier`,
`approved_by` or `state` field appearing in a request body is **ignored**, recorded as an
`identity_field_ignored` / `privileged_field_ignored` audit event, and echoed back as
`identity_source: "verified_token"`. There is no code path in which caller-supplied JSON can set a
trust tier or an approval. Asserted by `tests/security/test_forged_identity.py`.

### 3.4 Retrieval guard contract

One SQL statement performs the gate *before* ranking. The predicate is:

```
tenant match ∧ source.status='active' ∧ principal ∈ source_acl(read)
  ∧ document.status='active' ∧ chunk.state='active'
  ∧ version_validity.state='active'
  ∧ effective_from ≤ :as_of_valid    ∧ (effective_to    IS NULL ∨ effective_to    > :as_of_valid)
  ∧ system_recorded_from ≤ :as_of_recorded ∧ (system_recorded_to IS NULL ∨ system_recorded_to > :as_of_recorded)
  ∧ chunk_id ∈ fts_chunks MATCH :query
```

followed by a post-SQL **integrity recheck** against the side-store manifest, which may only
*remove* rows. A reader never receives excluded IDs, counts, citations or snippets; an admin-only
`trace` may. If any policy, integrity or DB step raises, the guard returns **no results** and
`guard_enforced: true` with a `fail_closed` reason — never unguarded memory. No cross-request result
cache exists in the MVP (per blueprint §3), which is asserted by a test that greps the engine for
cache usage and by a revocation-visibility test.

### 3.5 HTTP surface

`POST /api/sources` · `POST /api/sources/{id}/revoke` · `POST /api/documents` ·
`POST /api/documents/{id}/versions` · `GET /api/documents/{id}/versions` · `POST /api/retrieve` ·
`POST /api/context-packs` · `POST /api/qa` · `GET /api/quarantine` ·
`POST /api/quarantine/{id}/{approve|reject|revise}` · `GET /api/conflicts` ·
`POST /api/conflicts/{id}/resolve` · `POST /api/snapshots` · `GET /api/snapshots` ·
`GET /api/snapshots/{id}/diff` · `GET /api/exposures` · `GET /api/exposures/{id}` ·
`GET /api/ledger` · `GET /api/sources` · `GET /api/audit` · `GET /healthz` · `GET /api/whoami` ·
`POST /api/demo/unguarded-comparison` (admin + explicit env flag; labelled synthetic baseline).

Ports: API `127.0.0.1:8002` (`MF_API_PORT`), dashboard `127.0.0.1:5174` (`MF_WEB_PORT`).
Localhost-only binding by default. Mutations require role `reviewer` or `admin`.

---

## 4. Pinned dependencies

Exact resolved versions are written to `uv.lock` and `apps/dashboard/package-lock.json` by
`make setup`; the floors below are what `pyproject.toml` / `package.json` declare. `docs/VERIFICATION.md`
records the versions actually installed at verification time.

| Layer | Declared | Why |
|---|---|---|
| Python | `>=3.12` | `datetime.UTC`, `sqlite3` with FTS5 |
| fastapi | `>=0.118,<0.200` | ASGI routing + OpenAPI generation |
| pydantic | `>=2.11,<3` | v2 validation, strict models |
| pydantic-settings | `>=2.7,<3` | env-driven config |
| uvicorn[standard] | `>=0.37,<0.40` | dev server |
| python-multipart | `>=0.0.20,<0.1` | bounded file upload |
| pytest / pytest-cov | `>=8.3,<9` / `>=6,<8` | test runner |
| httpx | `>=0.28,<0.30` | ASGI transport for API tests |
| ruff / mypy | `>=0.14,<0.20` / `>=1.14,<2` | lint / typecheck |
| scikit-learn, numpy | optional `embeddings` extra | TF-IDF research baseline only |
| react, react-dom | `19.x` | dashboard |
| vite, @vitejs/plugin-react | `7.x` / `5.x` | build + dev server |
| typescript | `5.9.x` | typecheck |
| tailwindcss, @tailwindcss/vite | `4.x` | styling |
| @playwright/test | `1.56.x` | E2E + screenshot capture |

No cloud account, model key or paid API is required by `setup`, `dev`, `smoke`, `test`, `eval`,
`verify` or `screenshots`. The LLM adapter is an interface with a null default.

---

## 5. Test approach

| Suite | Path | What it proves |
|---|---|---|
| unit | `tests/unit/` | normalization + evidence spans, each detector rule, quotation mitigation, claim extraction/normalization, policy transition table, chunk offsets, bitemporal interval maths, manifest digests |
| integration | `tests/integration/` | real ingest → real FTS5 retrieve on a real file-backed DB; version supersession; review transitions; SDK/API parity; directory importer; context packs |
| seed vectors | `tests/integration/test_release_vectors.py` | loads `TEST_VECTORS.json`, runs **all 12** cases, each in its own disposable DB, seeding declared tenants/principals/sources and the reference policy first, asserting the declared `expected` keys against real DB and retrieval output |
| security | `tests/security/` | cross-tenant text/metadata/citation/count/trace leakage, forged identity and privileged fields, self-declared authority, revocation and tombstones, stale-index bypass (4 test-only injection paths), integrity mismatch, Unicode/homoglyph/bidi, benign-quotation false positives, re-ingestion resurrection, path traversal + symlink escape in the importer, size/content-type limits, auth on mutations, HTML escaping of untrusted previews, SQL-injection-shaped queries, fail-closed on injected DB error |
| e2e | `tests/e2e/` | Playwright drives the real dashboard against the real API; captures the four required screenshots; asserts rendered values come from the backend, not fixtures |
| eval | `evals/` | 178 labelled cases × 4 conditions; TP/FP/TN/FN, precision/recall/F1, poison exposure rate, benign recall@3, false-quarantine rate, p50/p95 ingest + retrieval latency, held-out perturbation split reported separately |

**Isolation:** every test gets a fresh temp DB (`tmp_path`); no test depends on another's state; no
network; no model key. Security tests are marked `security` and the CI job fails if any
`security`-marked test is deselected or skipped (`scripts/assert_no_skipped_security.py`).

**Evidence discipline:** a gate is PASS only when a named command was executed and its observed
output is quoted in `docs/ACCEPTANCE_STATUS.md`. Anything unexecuted is `NOT VERIFIED` with the exact
retry command. `make verify` is the release truth source.

---

## 6. Known risks carried into implementation

1. **Lexical detector ceiling** — broad semantic poisoning cannot be guaranteed caught; the
   dataset's held-out perturbation split is the overfitting check and the honest ceiling report.
2. **Legitimate-change false quarantine** — the `conflicting_but_legitimate` and
   `legit_approved_policy_update` families exist to measure this; it is a first-class failure mode.
3. **Integrity is relative** — SHA-256 + side-store manifest detects post-index mutation of the
   content DB only. An attacker holding both stores defeats it. Documented, not papered over.
4. **Bitemporality claim** — the term is used only if both valid-time and system-time predicates are
   implemented and tested; otherwise the gate is flagged (blueprint §3).
5. **Environment** — this session's egress policy initially blocked PyPI/npm/Docker Hub; see
   `docs/VERIFICATION.md` for what was and was not installable and executable at verification time.
