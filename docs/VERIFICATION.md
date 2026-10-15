# Verification report

What was actually executed, on what, with what result. Nothing in this file is inferred from code
reading; every line corresponds to a command that ran.

---

## Environment

Two runs are reported. The **first** (2026-10-14) was made in a sandbox whose egress policy blocked
every package registry, so parts of the toolchain had to be substituted. The **second**
(2026-10-15) was made after registry access became available, and re-ran everything against the
real toolchain. Where the two disagree, the second supersedes the first; the first is kept because
deleting it would hide which results were once produced by a substitute.

| | Run 1 — 2026-10-14 | Run 2 — 2026-10-15 (current) |
|---|---|---|
| **OS** | Linux 6.18.44 x86_64 (container) | Linux 6.18.44 x86_64 (container) |
| **Python** | 3.13.16 | **3.12.3** (the contract's floor, and CI's version) |
| **SQLite** | 3.45.1, FTS5 present | 3.45.1, FTS5 present |
| **Node** | v22.22.0 | v22.22.0 |
| **Installer** | none (no registry) | **uv 0.11.32**, `uv sync --extra dev --locked` against a committed `uv.lock` |
| **pytest** | substituted by `scripts/pytest_fallback.py` | **real pytest 8.4.2** |
| **HTTP server** | substituted by the fallback adapter | **real FastAPI 0.143.1 on uvicorn 0.39.0** |
| **Ruff** | 0.16.8 | 0.17.0 |
| **mypy** | not installable — BLOCKED | **1.20.2** |
| **Browser** | Chromium via Playwright 1.56.0 | Chromium via Playwright 1.56.0 |
| **Network** | registries **403** | registries reachable |

### What run 2 changed

1. **The suites ran under real pytest.** Same 302 tests, same result: `302 passed, 0 failed,
   0 skipped`. The fallback runner had not been hiding a failure.
2. **The live stack ran the real FastAPI app.** `./scripts/devstack.sh start` under the project
   venv starts `uvicorn app.main:app`; the `server: uvicorn` response header confirms it. All 33
   browser checks pass against it, so the browser evidence below is no longer produced by a
   substitute.
3. **mypy ran and is now a passing gate**, not a blocked one — after 24 real errors were fixed
   (see the defect log).
4. **Two defects surfaced that only the real toolchain could surface.** Both are recorded in the
   defect log: a mypy-visible `.upper()` on a possibly-`None` field, and a security-gate script
   that silently counted zero executed tests under real pytest.
5. **Docker remains BLOCKED here** — no daemon in this sandbox. It is the single remaining
   unverified gate locally, and the project's own GitHub Actions run reports the
   "Container images build" job as successful.

---

## Executed commands and results

### Engine and suites

All commands below are from run 2, under `uv run` (real pytest, real FastAPI).

| Command | Exit | Result |
|---|---|---|
| `python -m memory_firewall.cli doctor` | 0 | FTS5 OK, SQLite 3.45.1, schema `2026-10-14.1` |
| `pytest tests` | 0 | **302 passed, 0 failed, 0 skipped** in 24.3s |
| `pytest tests/unit` | 0 | 107 passed |
| `pytest tests/integration` | 0 | 75 passed |
| `pytest tests/security` | 0 | 119 passed |
| `pytest tests/integration/test_release_vectors.py` | 0 | **14 passed** — all 12 `TEST_VECTORS.json` cases, each in its own disposable database |
| `python scripts/assert_no_skipped_security.py` | 0 | **executed=119 skipped=0** — "every security test executed and passed" |
| `python -m memory_firewall.cli scenarios` | 0 | **12/12 scenarios passed (64 assertions)** |
| `python -m memory_firewall.cli smoke` | 0 | verdict **PASS** across 6 mandatory scenarios |
| `python examples/sdk_quickstart.py` | 0 | trusted ACTIVE, poison QUARANTINED, answer cited `company-policy#v1` |
| `python examples/support_copilot/copilot.py` | 0 | 5 scripted questions; declines the one with no authorised source |

### Quality gates

| Command | Exit | Result |
|---|---|---|
| `ruff check .` | 0 | **All checks passed!** (ruff 0.17.0) |
| `ruff format --check .` | 0 | **71 files already formatted** |
| `npm run build --prefix apps/dashboard` | 0 | typecheck + emit, **offline** (zero runtime dependencies) |
| `mypy` | 0 | **Success: no issues found in 32 source files** (mypy 1.20.2, `disallow_untyped_defs`) |
| `docker build -f Dockerfile.api .` | — | **BLOCKED**, no daemon here. Retry: `docker build -f Dockerfile.api -t memory-firewall-api:dev .` |

Ruff found three genuine defects that no executed test could have caught, all fixed:

- `apps/api/app/main.py` used `sys` without importing it — a `NameError` on a FastAPI route that
  could not be executed in this environment;
- a dead local in `testing.py`;
- a hardcoded-password heuristic hit on a constant holding a password-*reset runbook*, resolved by
  renaming it rather than silencing the rule.

It also silently reformatted `CLAUDE.md` (Ruff 0.16 formats Python blocks inside Markdown). That
file is a normative contract input, so it was restored byte-for-byte and all Markdown is now
excluded from the formatter.

### Live application

Started with `uv run ./scripts/devstack.sh start` — dashboard on `127.0.0.1:5174`, `/api/*` served
by **the real FastAPI app on uvicorn** (`server: uvicorn` in the response headers).

| Command | Exit | Result |
|---|---|---|
| `curl 127.0.0.1:5174/healthz` | 0 | `status=ok, fts5=true, guard_enforced=true` |
| `python scripts/run_e2e.py` | 0 | **33/33 browser checks passed**, 0 console errors |
| `python scripts/capture_screenshots.py` | 0 | **10 screenshots** written to `docs/assets/` |

A hand-written HTTP pass over the full workflow (15 checks: retrieve → ingest poison → re-retrieve →
cross-tenant → forged fields → quarantine → approve → reject → context pack → unguarded comparison →
scenario run → trace visibility → reader-cannot-ingest → ledger → conflicts) passed 15/15 after two
defects found during that pass were fixed (see below).

### Measurement

`python -m evals.runner` (exit 0), 178 labelled cases × 4 conditions:

| condition | poison exposure | stale-index exposure | false quarantine | curated QA@3 |
|---|---:|---:|---:|---:|
| Naive unguarded RAG | 3.5% | 10/10 | 0.0% | 100% |
| Keyword-only screening | 3.5% | 10/10 | 7.5% | 100% |
| Write-time firewall only | 0.0% | 10/10 | 2.2% | 100% |
| **Write + retrieve guard** | **0.0%** | **0/10** | **2.2%** | **100%** |

Detection (full condition): TP/FP/TN/FN = **79/12/81/6**, precision **0.868**, recall **0.929**,
F1 **0.898**. Ingestion p50/p95 **13.7 / 19.7 ms**; guarded retrieval p50/p95 **9.4 / 18.8 ms**.
Held-out perturbation split: recall **0.889** vs **0.940** primary.

**All five pre-registered goals met.** Full scorecard: `evals/results/RESULTS.{json,md}`.

### Git hygiene

| Command | Result |
|---|---|
| `git check-ignore private/Memory_Firewall_Research_Interview_Guide.pdf` | exit 0 — ignored |
| `git ls-files private/` | empty |
| `git ls-files .env` | empty |
| `git ls-files '*.sqlite3'` | empty |
| `git ls-files \| wc -l` | 137 tracked files (136 + `uv.lock`) |

### `make verify`

Last full run (run 2, with the stack up): **20 passed · 0 failed · 1 blocked**, exit 2. The single
blocked check is Docker, which has no daemon in this sandbox; it is reported as NOT VERIFIED,
never as passing. `docs/verify-report.json` carries the machine-readable record.

Exit 2 — not 0 — is the correct outcome and the script is designed to produce it: a check that
could not run is not a check that passed.

---

## Defects found during verification

Verification is only worth reporting if it found things. It found these, all fixed and
re-verified:

| # | Found by | Defect |
|---|---|---|
| 1 | detector unit tests | **Unicode tag-character smuggling evaded detection entirely** — normalisation *deleted* `U+E0020–E007E`, which is exactly what the attack relies on. Now decoded back to ASCII and flagged. |
| 2 | `make eval` | **The quotation mitigator was an open evasion route** — containment alone (quotes, a code fence) downgraded a finding, so wrapping a payload in quotes defeated it, and a fake ` ```system ` fence mitigated *itself*. Rewritten; recall 42%→93% and false quarantine 7.5%→2.1% simultaneously. |
| 3 | unit tests | **Unit-mismatch masking in claims** — "14 business days" vs "14 calendar days" produced no conflict because the equality check ran before the unit check. |
| 4 | integration tests | **Approving a chunk left its version's gate shut**, so a reviewer could approve the only chunk of a quarantined document and it stayed unretrievable with no indication why. |
| 5 | live HTTP pass | **Admin exclusion trace was always empty** — withheld chunks are not in the FTS index, so an index-based trace could not show the very rows an operator needs. Now supplemented by an index-independent scan. |
| 6 | live HTTP pass | **The side-by-side comparison showed no difference**, because the "unguarded" baseline searched the *guarded* index. A pipeline with no write gate would have indexed everything; it now scans the chunk table. |
| 7 | support copilot demo | **Stopwords matched everything** — "What is the CEO's home address?" returned a confident refund answer. Function words are now dropped from queries, which also lifted curated-QA recall@3 to 100%. |
| 8 | support copilot demo | **Scope-blind answer selection** — "What is the refund period?" answered with the VIP window. Scope match now ranks above trust tier. |
| 9 | browser E2E | **Three inline `style` attributes were silently dropped** by the dashboard's own CSP. |
| 10 | browser E2E | **Tab counters called reviewer-only endpoints as a reader**, producing console 403s. |
| 11 | **red-team review** | **HIGH: unauthenticated admin-token disclosure.** The fallback adapter defaulted the demo-token listing *on* while FastAPI defaulted it *off*, handing admin bearer tokens for both tenants to any unauthenticated caller. Both now default off, loopback-only, with a parity test. |
| 12 | **red-team review** | Readers could read not-yet-effective content via a future `as_of_valid`. Now tagged `NOT_YET_IN_FORCE`, with a config switch to restrict it; not blocked by default because MF-SEED-05 requires readers to ask about future dates. |
| 13 | **red-team review** | The bypass suite exercised 7 of the 10 predicates the guard enforces. Three modes added; now 10/10. |
| 14 | `ruff` | `sys` used without import on a FastAPI route — would have raised `NameError` in any environment that *could* run FastAPI. |
| 15 | **real `mypy`** | `_answer_refund_question` called `.upper()` on a claim's `region`, typed `str \| float \| None`. A claim parsed without a region would have raised `AttributeError` while building an answer — on the answer path, not a test path. Both scope fields are now narrowed before formatting. |
| 16 | **real `pytest` in CI** | `scripts/assert_no_skipped_security.py` scraped `"N passed"` out of console output, but `addopts` already contains `-q`, so its own extra `-q` made `-qq` and suppressed the summary line. The gate that exists to catch silently skipped security tests therefore reported **executed=0** and failed the build — against a suite that had just passed 119/119. It now reads counts from a JUnit XML report, which no verbosity flag can take away. |
| 17 | **real `mypy`** | `engine.document_versions` built `out` as an inferred `dict[str, Collection[Any]]`, so appending to `out["versions"]` was a type error; and 18 defensive `# type: ignore` comments written blind (while mypy could not run) were masking three genuine `list(object)` call errors in the detector. Replaced with typed accessors `NormalizationResult.events()` and `event_index()`. |

Found and **not** fixed, deliberately: the red-team review wrote **10 original payloads that land
ACTIVE**. That is the honest ceiling of a deterministic detector, published in
`docs/RED_TEAM_REVIEW.md` rather than patched away case by case. The compensating control added in
response is provenance tagging — every chunk from a weakly-trusted source is tagged
`treat_as_data_not_instructions` whether or not a rule fired.

---

## Limitations and unresolved items

1. **Not verified here: Docker image builds.** No daemon in this sandbox. Retry:
   `docker build -f Dockerfile.api -t memory-firewall-api:dev .`. The project's GitHub Actions run
   reports its "Container images build" job as successful, which is evidence from CI rather than
   from this machine.
2. **No `package-lock.json` is committed.** `uv.lock` now is, and CI installs with
   `uv sync --extra dev --locked`, so the Python side is reproducible. The npm side has a single
   devDependency pinned to an exact version; run `npm install` once with registry access and
   commit `apps/dashboard/package-lock.json` to close the gap.
3. **The benchmark is synthetic, single-domain and single-author**, with no adaptive adversary.
   Held-out performance is reported separately precisely because of this.
4. **Latency figures describe a small local corpus on one machine** and are not a general
   performance claim.
5. **Docker Compose on localhost is not a deployment.** `docs/SECURITY.md` §"The demo profile is not
   a deployment" lists what would still be required.

## Reproducing this

```bash
make setup
./scripts/devstack.sh start     # or: make dev
make verify                     # 0 = all passed · 1 = a check failed · 2 = something blocked
make eval                       # rewrites evals/results/RESULTS.{json,md}
make screenshots                # recaptures docs/assets/*.png from the running app
```
