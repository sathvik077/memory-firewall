
# ACCEPTANCE_EVIDENCE_MATRIX.md

This is a **definition of evidence**, not a claim that implementation or tests have passed. Once the project is built, copy this into `docs/ACCEPTANCE_STATUS.md` and add `Status`, `Evidence path`, `Command`, `Observed result`, `Date` to each row. PASS requires direct observed evidence, not a screenshot of a mockup. Release status is **NOT READY** unless every mandatory gate has passing evidence and the complete `make verify` passes.

## Evidence naming conventions

- `pytest` unit/integration/security tests: `tests/unit/test_*.py`, `tests/integration/test_*.py`, `tests/security/test_*.py`
- Release fixture runner: `tests/integration/test_release_vectors.py` (or named equivalent) loads all seed cases and asserts real outputs.
- Playwright: `tests/e2e/*.spec.ts` with snapshots made from actual UI/backend, not mocked metrics.
- Evaluation: `evals/RESULTS.json` and `evals/RESULTS.md` created by `make eval` with case ids and errors.
- Verification: `docs/VERIFICATION.md` + `docs/ACCEPTANCE_STATUS.md` (locally observed facts) + CI logs.
- If an integration only works with an external credential, it is **optional**, not evidence for required offline release.

## Mandatory gate mapping

| Gate | Proof required | Suggested evidence source |
|---|---|---|
| MF-01 | Offline dev setup | make setup/dev /healthz |
| MF-02 | Real chunk ingestion and quarantine | test post-content scan DB status |
| MF-03 | Real FTS5 retrieval rank | SQLite query execution test |
| MF-04 | Unsafe chunks excluded from context | pre-retrieval fixture bypass test |
| MF-05 | Forgery cannot set trust tier | ingest source lookup vs spoof JSON |
| MF-06 | Reviewer trusted credentials | auth cross-role operation test |
| MF-07 | Tenant/ACL isolation | text/metadata/citation/trace tests |
| MF-08 | Temporal approved revisions | before/after/as-known-at tests |
| MF-09 | Conflict evidence not universal truth | structured-claim conflict tests |
| MF-10 | Review state/audit transactionality | promote/quarantine rollback tests |
| MF-11 | Revoked/tombstone never retrieved | FTS revocation/cache regression |
| MF-12 | SDK+local adapter | SDK call + safe importer test |
| MF-13 | Provenance context packs | source IDs and ACL evidence test |
| MF-14 | Real forensic dashboard | Playwright backend-connected UI check |
| MF-15 | Eight offline reproducible scenarios | test fixture resets and IDs |
| MF-16 | Unguarded vs guarded cause/effect | same corpus side-by-side query outputs |
| MF-17 | Real screenshots/docs | Playwright capture and README asset check |
| MF-18 | 120+ labeled cases and metrics | eval results JSON validation, TP/FP/TN/FN |
| MF-19 | Four baselines same dataset | eval methodology and identical IDs |
| MF-20 | Benign trusted update vs attack | v1/v2/poison claim timeline test |
| MF-21 | All commands and CI checks | make verify + type/build lint test outputs |
| MF-22 | Defensive regression suite | spoofing/Unicode/ACL cache/path traversal |
| MF-23 | Safe API and previews | size/type/auth/escaping SSRF negative tests |
| MF-24 | Bounded security/integrity claims | security doc key boundary and evidence |
| MF-25 | Docker and git hygiene | image build, git check-ignore private/ |
| MF-26 | Five cited primary references | docs/RESEARCH.md primary source links |
| MF-27 | Verification report factual | docs/VERIFICATION.md command/result/limits |

## Release review: required independent red-team questions

1. Can untrusted user/model content forge an authority field or cross a trust boundary?
2. Does any policy, auth or DB exception result in permissive behavior?
3. Can an unauthorized side effect or poisoned context exposure occur while dashboard says BLOCKED?
4. Is any required test skipped by default, or does an evaluation chart use fabricated data?
5. Can a clean user follow the README without secret keys and reproduce screenshots or causal demo?
6. Are limitations, bypass cases and exact coverage clearly documented?

**Disposition:** Mark NOT READY if any critical flaw remains; do not conceal failures to meet a release date.
