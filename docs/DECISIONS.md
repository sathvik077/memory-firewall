# Decision log

Each entry is a choice that could reasonably have gone the other way, with what it cost.

---

## D1 — SQLite with FTS5, not a vector database

**Decision.** Lexical retrieval over SQLite FTS5 is the default and only required path. An
embeddings adapter is an optional extra.

**Why.** The thesis is about the *gate*, not the ranker. Putting the gate inside the SQL statement
that performs the search is what makes "ineligible content cannot be ranked" a structural property
rather than an application convention — with an external vector store the filter inevitably becomes
a post-hoc step over results the store already assembled, which is precisely the design this project
argues against. SQLite also makes the demo a `git clone` with no services to run.

**Cost.** Lexical retrieval is weaker than embeddings on paraphrase. The evaluation measures the
guard, not the ranker, so the headline numbers are not affected — but a production deployment would
want both, and would need to re-establish the gate property inside whatever vector store it chose.

---

## D2 — The detector is deterministic, and its ceiling is published

**Decision.** Rules with stable IDs, severities and evidence spans. No model in the detection path.

**Why.** A security control that cannot explain itself cannot be reviewed, and a probabilistic one
cannot be regression-tested. Every finding points at a character span in the original document.

**Cost.** Real and measured: recall 0.929 on the labelled set, and an independent reviewer wrote ten
original payloads that walk straight past it. Those are published in `docs/RED_TEAM_REVIEW.md`
rather than quietly fixed, because they are the honest ceiling of the approach. The compensating
control is provenance tagging, not a claim to have closed the gap.

---

## D3 — Containment alone never mitigates a finding *(changed after measurement)*

**Decision.** A match is downgraded only when the document *frames* it as discussion: an explicit
counter-instruction, or two independent framing signals. Quotes or a code fence alone do nothing.

**Why it changed.** The first implementation treated containment as sufficient. That is an open
evasion route — wrap the payload in quotes — and worse, a fake ` ```system ` fence *is itself* the
attack, so mitigating it on the strength of the fence was exactly backwards. Measurement made it
obvious: malicious recall 42%, benign false quarantine 7.5%.

**Result.** After the rewrite: recall 93%, false quarantine 2.1%. Both improved, which is the sign
that the original rule was wrong rather than merely tuned differently.

---

## D4 — Unicode tag characters are decoded, not deleted

**Decision.** `U+E0020`–`U+E007E` are mapped back to their ASCII equivalents during normalisation.

**Why.** Deleting them is what the attack relies on: the hidden instruction vanishes before any rule
sees it. A test wrote `ignore all previous instructions` entirely in tag characters and it landed
ACTIVE with no findings. Decoding restores the text, every rule reads it normally, and the presence
of tag characters is itself flagged high-severity because there is no legitimate use in prose.

---

## D5 — Bitemporal from the start, or not called bitemporal at all

**Decision.** Append-only `version_validity` rows carrying valid time *and* system time. A state
change closes the current row in system time and inserts a new one; nothing is mutated.

**Why.** The blueprint is explicit that the word may only be used if both axes are implemented and
tested. Without system time, the time machine can only say what was in force — not what we *knew* —
and "as known in October, December was 30 days" is the only version of that feature that is
actually useful in an incident.

**Cost.** Noticeably more complex than a `status` column, and supersession has to write two rows
instead of updating one.

---

## D6 — No cross-request cache anywhere

**Decision.** A connection per transaction, no result cache, no memoisation in the retrieval path.

**Why.** The contract requires that a revoked ACL cannot leak through a stale cache. The cheapest
way to be certain is to have nothing to invalidate. A test greps the retrieval path and the engine
for caching primitives and fails if one appears.

**Cost.** Throughput. Correct for a local forensic tool; a production deployment adding a cache
inherits the invalidation problem and must solve it explicitly.

---

## D7 — The dashboard has no framework and no bundler *(deviation from the brief)*

**Decision.** TypeScript compiled to native ES modules, hand-written CSS, zero runtime dependencies.
The brief specified React + Vite + Tailwind.

**Why.** The build environment's egress policy blocked the npm registry entirely (403 on
`registry.npmjs.org`), so React, Vite and Tailwind could not be installed, and a dashboard that
cannot be built cannot be screenshotted, browser-tested, or demonstrated. The choice was between a
dashboard verified to work and a dashboard written to a spec and never run. Given the contract's
own priority order — working integration above aesthetics — the former wins.

It turned out to be a good trade on its own merits: `npm ci` succeeds offline, the production image
is a static file server rather than a Node runtime, and a security tool's own UI carries no
transitive dependency surface. The strict CSP it ships with blocked Playwright's `wait_for_function`
during E2E development, which is how we learned it was genuinely enforced.

**Cost.** No component ecosystem, hand-rolled DOM helpers, and a port would be needed to adopt
React later. The panes are thin over a typed API client, so the port would be mechanical.

---

## D8 — FastAPI is the API, with a fallback adapter for this environment

**Decision.** `apps/api/app/main.py` is the FastAPI app the contract specifies. `scripts/serve_dashboard.py`
carries a fallback adapter that serves the same routes in-process over the same engine, used only
when FastAPI is not importable.

**Why.** Same reason as D7: FastAPI could not be installed in the original build environment, and
without *some* HTTP surface the dashboard, the browser E2E and the screenshots would all be
unverifiable.

**Status.** Resolved as of 2026-10-15. FastAPI is installed, `make dev` and CI both start the real
app on uvicorn, and the browser suite passes 33/33 against it. The adapter stays because it costs
nothing to keep and makes the dashboard usable with zero Python dependencies — but it is now the
fallback it was always meant to be, not the thing being tested.

**Cost, and what it caused.** Two routing layers can drift — and they did. An independent review
found the fallback defaulting the demo-token listing *on* while FastAPI defaulted it *off*, which
handed admin bearer tokens to an unauthenticated caller. Fixed, and `tests/integration/test_route_parity.py`
now asserts the two adapters agree on routes and on that gate. Every security decision lives in the
engine precisely so the blast radius of this kind of drift stays in the routing layer.

---

## D9 — `ALLOW_WITH_FLAGS` exists so security documentation stays usable

**Decision.** A fifth decision between "allow" and "hold for review": retrievable, but visibly
flagged.

**Why.** A security runbook that quotes `ignore previous instructions` as a training example is the
most important benign class in this product. Hard-blocking it makes the tool unusable for the exact
teams most likely to adopt it. Flagging keeps it available and visible.

**Cost.** Measured, not assumed: the benign-flag rate and false-quarantine rate are both in the
scorecard.

---

## D10 — Tests use `unittest`-compatible structure and run under a fallback runner here

**Decision.** Tests are ordinary pytest tests. Where pytest cannot be installed, `scripts/pytest_fallback.py`
executes the same unmodified files with a documented subset of pytest's behaviour.

**Why.** The contract forbids claiming a test passed without executing it. The alternative was 302
written-but-unexecuted tests, which is exactly the false completion the contract prohibits.

**Cost.** The fallback does not implement plugins, coverage, xdist, monkeypatch or assertion
rewriting, so failure output is a plain `AssertionError`. `docs/VERIFICATION.md` records which
runner produced which numbers.

**Status.** Resolved as of 2026-10-15: all 302 tests now run under real pytest 8.4.2 with the same
result, so the substitute was not hiding a failure. `make test` prefers real pytest whenever it is
importable and falls back only otherwise.

**What this cost anyway.** Writing the harness against the fallback's output format left a real
bug in `scripts/assert_no_skipped_security.py`: it scraped `"N passed"` from console text, and
under real pytest the project's own `-q` in `addopts` plus the script's `-q` produced `-qq`, which
prints no summary line. The security-skip gate then read zero executed tests and failed CI against
a suite that had just passed 119/119. It now reads a JUnit XML report. The general lesson is in
the cost column of D7 as well: a substitute you build the tooling around stops being invisible.

---

## D11 — The eval dataset was written by an agent kept blind to the detector

**Decision.** An independent agent authored all 178 cases without reading the detector, and
deliberately added benign cases at `external_untrusted` so trust tier alone could not separate the
set.

**Why.** A dataset written against a rule list measures the rule list. The held-out perturbation
split (recall 0.889 vs 0.940 primary) only means something because the author could not see the
rules.

---

## D12 — Measurement methodology was corrected twice, mid-flight

**Decision.** Report both *exposure* (realistic topical query against the whole corpus) and
*reachability* (targeted query), and measure utility on a separate curated QA set.

**Why.** The first version measured recall@3 for each case against 177 competing near-duplicates,
which measures ranking competition, not whether the guard let the right answer through. The second
problem was subtler: the stale-index probe used a generic query, so the forced-in poison did not
rank top-5 and every condition scored 0/10 — the headline result was being hidden by bm25 rather
than by the guard. Both are now measured the way the question is actually asked, and the
guard-attributable utility delta (0.0) is reported separately from absolute recall.

---

## D13 — Unmet goals are reported as unmet

**Decision.** `make eval` prints and records pre-registered goals it did not meet; `make verify`
exits 2 when a mandatory check could not run, rather than treating "blocked" as "passed".

**Why.** The contract's single sharpest instruction. When curated-QA recall was below target, the
fix was to report *why* (every condition missed the same question identically, so it was a bm25
ambiguity, not the guard) — not to edit the question. It later reached 100% because of a genuine
relevance fix found by the copilot demo giving a nonsensical answer.
