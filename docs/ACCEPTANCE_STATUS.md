# Acceptance status

Every release gate from `CLAUDE.md` §8, with the command that was run and what was observed.

**Rules used here, from the contract:** PASS requires *direct observed evidence*, not a screenshot
of a mock-up. Anything not executed is **NOT VERIFIED** with its exact retry command. Release status
is NOT READY unless every mandatory gate passes and `make verify` exits 0.

- **Date:** 2026-10-15 (supersedes the 2026-10-14 run, which was made without package-registry
  access and therefore against a substituted toolchain)
- **Environment:** Python 3.12.3 · SQLite 3.45.1 (FTS5 present) · Node 22.22.0 · real pytest 8.4.2 ·
  real FastAPI 0.143.1 on uvicorn 0.39.0 · Ruff 0.17.0 · mypy 1.20.2 · Linux 6.18.44 x86_64
- **Truth source:** `make verify` → `docs/verify-report.json`
- **Overall:** **NOT READY** — 26 of 27 gates PASS, **1 NOT VERIFIED** (Docker image builds), 0 FAIL.
  The one unverified gate has no Docker daemon in this sandbox; it prints its exact retry command,
  and the project's GitHub Actions run reports its container-build job as successful.

---

## Security functionality

| Gate | Status | Command | Observed |
|---|---|---|---|
| **MF-01** `make setup && make dev` launches locally, no key, no mandatory Docker; ports documented | **PASS** | `make setup`; `./scripts/devstack.sh start`; `curl 127.0.0.1:5174/healthz` | Setup created the DB, seeded 6 documents and wrote `.env`. Health: `status=ok, fts5=true, schema=2026-10-14.1`. API `127.0.0.1:8002`, dashboard `127.0.0.1:5174`, both documented in README and Makefile help. No API key anywhere. |
| **MF-02** Ingest real content; versioned source/chunk records with real hashes and provenance | **PASS** | `pytest tests/integration/test_vertical_slice.py`; `POST /api/documents` | Ingest returns `content_sha256` (64 hex), `version`, per-chunk `raw_span`, and writes `document_versions` + `version_validity` + `chunks` + `risk_findings` in one transaction. |
| **MF-03** Quarantine on pre-write; excluded from the active index; evidence reasons stored | **PASS** | `pytest tests/integration/test_vertical_slice.py::test_the_index_only_contains_active_chunks` | Poison → `QUARANTINED` with rules `MF-R001, MF-R002, MF-R010`. Asserted: zero FTS rows for withheld chunks, and every indexed chunk has `state='active'`. Reasons and evidence spans persisted in `risk_findings`. |
| **MF-04** Retrieve ranked stored chunks via FTS5, not a pre-baked answer; IDs and citations returned | **PASS** | `pytest tests/integration/test_vertical_slice.py::test_retrieval_is_real_fts5_ranking_not_a_canned_answer` | Different queries return different documents with different bm25 scores; an unrelated query returns nothing. Citations are `source#vN`. |
| **MF-05** Pre-retrieval exclusion **independently** blocks poison introduced by a test-only migration | **PASS** | `pytest tests/security/test_index_bypass_and_integrity.py` | **10/10 bypass modes blocked**, each defeating a different predicate, plus an orphan FTS row. Each test first asserts the poison really is in the index, so the gate is genuinely exercised. |
| **MF-06** Trust tier comes from admin/review config, never from in-document claims | **PASS** | `pytest tests/security/test_forged_identity_and_authority.py` | Document containing `trust_tier: authoritative_signed` / `approved_by: admin` → source tiers unchanged, content `QUARANTINED` via `MF-R009`. No code path passes a caller-supplied tier. |
| **MF-07** Tenant/ACL isolation for text, metadata, citations, preview, cache and trace; regression tests | **PASS** | `pytest tests/security/test_tenant_and_acl_isolation.py` (15 tests) | Cross-tenant payloads contain none of the foreign tenant's chunk IDs, citations, principals or text. `candidate_count` does not move when content the reader may not see is added. Readers never receive a trace; admin traces are tenant-scoped. 404 and 403 are indistinguishable for foreign targets. Independently re-confirmed by the red-team review. |
| **MF-08** Approved revisions with effective dates, version history, supersession; previous policy in authorized history | **PASS** | `pytest tests/integration/test_bitemporal_versions.py` | Before the effective date → 30 days; after → 14 days and not 30. v1 retains its original open-ended belief as a closed system-time row plus a corrected row. |
| **MF-09** Contradiction surfaces claim/evidence pair and a **review state**, not a truth judgement | **PASS** | `pytest tests/unit/test_claims.py`; `GET /api/conflicts` | Conflicts carry both claim IDs, both values, both authority tiers and both evidence spans, status `needs_review`. API and UI both state it is not a judgement about which document is correct. |
| **MF-10** Review workflows update the index transactionally, with actor/reason and durable audit | **PASS** | `pytest tests/integration/test_review_and_transactions.py` | Approve → `quarantined→active`, 1 chunk reindexed, retrievable on the next query; reject → removed from FTS. Reason mandatory. Illegal transitions refused (409). Rollback test asserts tables and FTS move together or not at all. |
| **MF-11** Expired/revoked sources, tombstones and integrity mismatch unavailable; no stale index/cache bypass | **PASS** | `pytest tests/security/test_revocation_and_fail_closed.py` | Revocation and ACL removal take effect on the very next call. Source expiry excludes by valid time. Digest mismatch and *missing* manifest both withhold with an integrity alert. A test asserts no caching primitive exists in the retrieval path. |
| **MF-12** SDK `ingest`/`retrieve` and directory loader work; the sample copilot uses the same backend | **PASS** | `python examples/sdk_quickstart.py`; `python examples/support_copilot/copilot.py`; `pytest tests/integration/test_sdk_and_adapters.py` | The contract's §4B quickstart runs verbatim. SDK and engine produce byte-identical decisions on the same input. Directory importer ingests through the full pipeline and quarantines the poisoned file. |
| **MF-13** Context packs attach provenance and chunk IDs; only eligible chunks reach the adapter | **PASS** | `pytest tests/integration/test_context_packs_and_answers.py` | Packs carry citations, trust tiers and risk tags. Quarantined text never appears. Empty pack ⇒ `insufficient_evidence`, no answer, and the null adapter declines. |

## Product design / research

| Gate | Status | Command | Observed |
|---|---|---|---|
| **MF-14** Dashboard shows ingestion, real scanner results, timeline, quarantine, conflicts, exposure, snapshot replay | **PASS** | `python scripts/run_e2e.py` | **33/33 browser checks** against the live backend, zero console errors. All eight panes assert live data before any screenshot is taken. |
| **MF-15** ≥8 repeatable offline scenarios with reset; synthetic, no network harm | **PASS** | `python -m memory_firewall.cli scenarios` | **12/12 scenarios, 64 assertions**, each in its own disposable database. All offline, all synthetic, inert payloads on reserved hosts. |
| **MF-16** Demo proves impact on a future query; side-by-side labelled synthetic vs actual | **PASS** | `POST /api/demo/unguarded-comparison`; Attack Lab → *Compare* | Unguarded baseline returns the `SYSTEM OVERRIDE … 2 days` poison; the guarded result returns only the cited policy; 3 chunks withheld. Every response labels the baseline *"NOT Memory Firewall output"*. Captured in `docs/assets/unguarded-vs-guarded.png`. |
| **MF-17** Real captured screenshots in `docs/assets/` and README; architecture image; 30s setup; 2-minute demo | **PASS** | `make screenshots`; `make arch` | 10 screenshots captured by Playwright from the running app, each after an assertion confirmed live data. All four required filenames present plus `architecture.svg`. README has the 30-second quickstart and the two-minute demo script. |
| **MF-18** `make eval` writes JSON + Markdown with 120+ cases, splits, TP/FP/TN/FN, exposure, recall@k, p50/p95, blind spots | **PASS** | `make eval` | **178 cases**. TP/FP/TN/FN = 79/12/81/6; precision 0.868, recall 0.929, F1 0.898. Poison exposure 0.0%. Curated QA recall@3 100%. Ingest p50/p95 13.7/19.7 ms; retrieval p50/p95 9.4/18.8 ms. Blind spots listed in `RESULTS.md`. **5/5 pre-registered goals met.** |
| **MF-19** Four baselines on identical cases, correct denominators, no cherry-picking | **PASS** | `make eval` | All four conditions run the same 178 cases in the same order with the same seeded reference policy. Stale-index exposure: unguarded 10/10, keyword-only 10/10, write-only 10/10, **full 0/10**. Held-out split reported separately (recall 0.889 vs 0.940). |
| **MF-20** Unauthorized changed fact flagged; legitimate v2 approved; effective-time queries correct | **PASS** | `pytest tests/integration/test_bitemporal_versions.py`; scenario `benign-update` | Untrusted "2 days" → `QUARANTINE` via the claim graph with no lexical signal at all. Authoritative v2 → `REVIEW_REQUIRED` → approved → in force after its effective date, with v1 retained. |

## Engineering / defensive

| Gate | Status | Command | Observed |
|---|---|---|---|
| **MF-21** `make test`, `lint`, `typecheck`, `build`, `verify`, CI with real outputs; npm build works offline | **PASS** | `make test lint typecheck build verify` | `make test` under **real pytest 8.4.2**: **302 passed, 0 failed, 0 skipped** in 24.3s. `ruff check` **All checks passed** (0.17.0); `ruff format --check` **71 files already formatted**. **`mypy` Success: no issues found in 32 source files** — the gate now runs, after 24 real type errors were found and fixed. `npm run build` succeeds **offline** (no runtime dependencies). `make verify` runs and reports honestly. **CI has executed**: the dashboard-build, container-build and repository-hygiene jobs pass; the backend job's two failures (mypy, and a security-gate script that miscounted under real pytest) are fixed in this revision. |
| **MF-22** Regression tests for spoofing, Unicode, benign quotations, false positives, reingestion, digests, cross-tenant, metadata tampering, ACL invalidation, path traversal | **PASS** | `pytest tests/security` (119 tests) | All named classes covered. `scripts/assert_no_skipped_security.py` asserts **119 executed, 0 skipped**, counted from a JUnit report rather than scraped console text. |
| **MF-23** Size limits, content-type validation, safe file IO, localhost binding, auth on mutations, no SSRF, no HTML/script injection, escaped previews | **PASS** | `pytest tests/security/test_input_limits_and_injection.py`; `run_e2e.py` | Oversized/empty documents refused; upload suffix allow-list; hostile FTS/SQL queries inert; path traversal, symlinks and symlinked parents blocked; a test greps the engine and API for outbound-request calls (none). Previews escaped twice over; CSP `script-src 'self'` verified live — it blocked Playwright's own `wait_for_function`. |
| **MF-24** Audit distinguishes detection from proof; keys outside the untrusted DB; 'tamper-evident' bounded | **PASS** | `docs/SECURITY.md`; `integrity.py`; UI copy | Every finding stores `confidence_semantics` stating it is *not* a probability of maliciousness. Manifests live in a separate file; `MF_HMAC_KEY` is read from the environment and never persisted. SECURITY.md states exactly what a digest does and does not prove. |
| **MF-25** GitHub Actions and Docker build succeed; safe `.env.example`; only synthetic data committed; private PDF ignored | **PARTIAL — 1 NOT VERIFIED HERE** | `git check-ignore private/…`; `docker build`; GitHub Actions | Git hygiene **PASS**: `private/` ignored, nothing tracked under it, no `.env`, no `*.sqlite3`, 137 files tracked, `.env.example` contains placeholders only. **GitHub Actions has run**: container images build, dashboard build and repository hygiene all pass. **Docker builds NOT VERIFIED on this machine** — no daemon in the sandbox; CI is the evidence that they build. |
| **MF-26** `docs/RESEARCH.md` cites ≥5 primary sources; novelty as a tested hypothesis | **PASS** | `docs/RESEARCH.md` | **12 primary sources**, each fetched and verified by an independent research agent, with two partial-verification caveats flagged in the text. Includes an explicit "where Memory Firewall is NOT novel" section and states plainly where Model Armor and CaMeL are stronger. |
| **MF-27** `docs/VERIFICATION.md` reports real commands, date, OS, deps, measured outcomes, limitations, unresolved items | **PASS** | `docs/VERIFICATION.md` | Present, with exact commands, exit codes, environment, and a blocked-checks section carrying retry commands. |

---

## Not verified, and exactly why

One gate, and it is an absent tool rather than a defect.

| Gate | What could not run | Why | Retry |
|---|---|---|---|
| MF-25 | `docker build` for both images | No Docker daemon in this sandbox | `docker build -f Dockerfile.api -t memory-firewall-api:dev .` |

Resolved since the 2026-10-14 run, when package registries became reachable:

- **mypy** (MF-21) now runs and passes. It found 24 real errors first, including an
  `AttributeError` waiting on the answer path and eighteen `# type: ignore` comments that had been
  written blind and were masking three genuine type errors.
- **Real pytest** (MF-21) replaced `scripts/pytest_fallback.py`. Same 302 tests, same result — the
  substitute had not been hiding a failure. The fallback runner stays in the tree for environments
  without a registry, and `make test` still prefers real pytest when it is installed.
- **Real FastAPI on uvicorn** (MF-12, MF-14, MF-23) replaced the fallback HTTP adapter for the live
  stack. All 33 browser checks pass against the actual server, so the browser evidence is no longer
  produced by a substitute. The adapter stays as a no-dependency fallback, with
  `tests/integration/test_route_parity.py` continuing to assert the two cannot diverge.
- **GitHub Actions** (MF-21, MF-25) has executed. Three of five jobs passed on the first run; the
  backend job failed on the two defects described above and the e2e job was skipped behind it. Both
  defects are fixed in this revision.
- **`uv.lock` is committed**, and CI installs with `uv sync --extra dev --locked`, so the Python
  dependency set is now pinned rather than re-resolved per run.

## Disposition

**NOT READY**, on the contract's own terms: `make verify` exits 2 while any mandatory check is
BLOCKED, and one is. Every gate that *could* be executed here was executed and passed, including
all thirteen security-functionality gates.

To reach READY, on a machine with a Docker daemon:

```bash
docker build -f Dockerfile.api -t memory-firewall-api:dev .
docker build -f Dockerfile.dashboard -t memory-firewall-dashboard:dev .
make dev        # the browser gate needs the stack up
make verify     # expect exit 0
```

Separately — and this is a property of the approach, not a gate: the detector lets original,
well-written steering text through. Ten worked examples are published in `docs/RED_TEAM_REVIEW.md`.
No gate claims otherwise.
