# Verification report

What was actually executed, on what, with what result. Nothing in this file is inferred from code
reading; every line corresponds to a command that ran.

---

## Environment

| | |
|---|---|
| **Date** | 2026-10-14 |
| **OS** | Linux 6.18.44 x86_64 (container) |
| **Python** | 3.13.16 |
| **SQLite** | 3.45.1, **FTS5 present** (asserted at startup; the engine refuses to run without it) |
| **Node** | v22.22.0 |
| **Ruff** | 0.16.8 |
| **Browser** | Chromium via Playwright 1.56.0 |
| **Database** | `data/memory-firewall.sqlite3` + `data/memory-firewall.sqlite3.manifests` |
| **Network** | **No outbound access to package registries.** `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` and `registry-1.docker.io` all return **403** from the egress proxy. |

### What that constraint changed

Three things, each with a consequence recorded here rather than hidden:

1. **`pytest` could not be installed.** The suites ran under `scripts/pytest_fallback.py`, which
   executes the same unmodified test files and supports a documented subset of pytest (fixtures
   including `yield` fixtures and `tmp_path`, `pytest.raises`, `pytest.mark`, `parametrize`,
   `unittest.TestCase`, `-k`/`-m`). It does **not** implement plugins, coverage, xdist, monkeypatch
   or assertion rewriting. The tests need no change to run under real pytest.
2. **`fastapi` could not be installed.** `apps/api/app/main.py` is the contracted FastAPI app and is
   what the Docker image runs; it could not be started here. The live stack served `/api/*` through
   the fallback adapter in `scripts/serve_dashboard.py`, which calls the **same engine** — only the
   routing layer differs, and `tests/integration/test_route_parity.py` asserts the two cannot
   diverge. **Every browser and HTTP result below was produced against the fallback adapter.**
3. **`mypy` and Docker could not run at all.** Recorded as NOT VERIFIED with retry commands.

`ruff` turned out to be present and was run for real.

---

## Executed commands and results

### Engine and suites

| Command | Exit | Result |
|---|---|---|
| `python -m memory_firewall.cli doctor` | 0 | FTS5 OK, SQLite 3.45.1, schema `2026-10-14.1` |
| `python scripts/pytest_fallback.py tests` | 0 | **selected=302 passed=302 failed=0 errors=0 skipped=0** |
| `… tests/unit` | 0 | 110 passed |
| `… tests/integration` | 0 | 78 passed |
| `… tests/security` | 0 | 113 passed |
| `… tests/integration/test_release_vectors.py` | 0 | **14 passed** — all 12 `TEST_VECTORS.json` cases, each in its own disposable database |
| `python scripts/assert_no_skipped_security.py` | 0 | **executed=113 skipped=0** — "every security test executed and passed" |
| `python -m memory_firewall.cli scenarios` | 0 | **12/12 scenarios passed (64 assertions)** |
| `python -m memory_firewall.cli smoke` | 0 | verdict **PASS** across 6 mandatory scenarios |
| `python examples/sdk_quickstart.py` | 0 | trusted ACTIVE, poison QUARANTINED, answer cited `company-policy#v1` |
| `python examples/support_copilot/copilot.py` | 0 | 5 scripted questions; declines the one with no authorised source |

### Quality gates

| Command | Exit | Result |
|---|---|---|
| `ruff check .` | 0 | **All checks passed!** |
| `ruff format --check .` | 0 | **71 files already formatted** |
| `npm run build --prefix apps/dashboard` | 0 | typecheck + emit, **offline** (zero runtime dependencies) |
| `python -m mypy` | — | **BLOCKED**, not installable. Retry: `uv sync --extra dev && python -m mypy` |

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

Started with `./scripts/devstack.sh start` — dashboard on `127.0.0.1:5174`, `/api/*` served in
process by the fallback adapter.

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
| `git ls-files \| wc -l` | 124 tracked files |

### `make verify`

Last full run: **16 passed · 3 failed · 2 blocked**, exit 1. The three failures were *this
document and `ACCEPTANCE_STATUS.md` not yet existing*, plus the two Ruff gates — all since fixed.
The two blocked checks (mypy, Docker) remain blocked and are reported as NOT VERIFIED, never as
passing. `docs/verify-report.json` carries the machine-readable record.

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

Found and **not** fixed, deliberately: the red-team review wrote **10 original payloads that land
ACTIVE**. That is the honest ceiling of a deterministic detector, published in
`docs/RED_TEAM_REVIEW.md` rather than patched away case by case. The compensating control added in
response is provenance tagging — every chunk from a weakly-trusted source is tagged
`treat_as_data_not_instructions` whether or not a rule fired.

---

## Limitations and unresolved items

1. **Not verified here:** mypy, Docker image builds, GitHub Actions. All three are blocked by this
   environment, all three have retry commands in `docs/ACCEPTANCE_STATUS.md`.
2. **The evidence above came from the fallback HTTP adapter**, not FastAPI. The engine is identical
   and route parity is asserted, but the FastAPI app itself has never been started.
3. **No `uv.lock` or `package-lock.json` is committed** — neither could be generated without a
   registry. `pyproject.toml` pins bounded ranges with upper bounds and the single npm
   devDependency is pinned to an exact version. Run `uv sync` and `npm install` once with network
   access and commit the locks.
4. **The test runner was not pytest.** See the environment note above.
5. **The benchmark is synthetic, single-domain and single-author**, with no adaptive adversary.
   Held-out performance is reported separately precisely because of this.
6. **Latency figures describe a small local corpus on one machine** and are not a general
   performance claim.
7. **Docker Compose on localhost is not a deployment.** `docs/SECURITY.md` §"The demo profile is not
   a deployment" lists what would still be required.

## Reproducing this

```bash
make setup
./scripts/devstack.sh start     # or: make dev
make verify                     # 0 = all passed · 1 = a check failed · 2 = something blocked
make eval                       # rewrites evals/results/RESULTS.{json,md}
make screenshots                # recaptures docs/assets/*.png from the running app
```
