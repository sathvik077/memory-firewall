# Security

## Reporting a vulnerability

Open a **private** security advisory on the repository, or email the maintainers. Please do not open
a public issue for an unfixed vulnerability. Include what you ran, what you observed, and what you
expected. A reproduction against the local demo is ideal; the whole stack runs offline.

This is a research and demonstration project. There is no SLA, and no bug bounty.

---

## What Memory Firewall claims, precisely

It is easier to trust a security tool that says what it does *not* do. Each claim below is bounded
deliberately, and each bound is enforced or measured somewhere you can check.

### It does claim

1. **Content that is not eligible cannot be ranked, counted, cited, previewed or returned.** The
   gate is inside the SQL statement that performs the search. Proven by forcing poison directly into
   the live index with the write guard bypassed, ten different ways, each breaking a different
   predicate: `tests/security/test_index_bypass_and_integrity.py`.
2. **Trust tier and identity cannot be set by a caller or by document text.** They come from
   administrative state and from `sha256(bearer token)`. Proven by
   `tests/security/test_forged_identity_and_authority.py`.
3. **Tenant and per-principal ACL isolation holds for text, metadata, citations, counters and
   traces**, and "forbidden" is indistinguishable from "does not exist" so status codes cannot be
   used as an existence oracle: `tests/security/test_tenant_and_acl_isolation.py`.
4. **The guard fails closed.** Any exception in the retrieval path yields an empty result with
   `fail_closed: true`. Proven by injecting a failing connection and a failing manifest store.
5. **Post-index mutation of the content database is detected**, because expected digests live in a
   separate file. A missing manifest fails *closed*, not open.
6. **Revocation and ACL changes take effect on the very next query**, because the MVP has no
   cross-request cache at all — there is nothing to invalidate, and a test asserts no caching
   primitive appears in the retrieval path.
7. **With no eligible evidence, no answer is produced.** The bundled copilot declines.

### It does not claim

1. **Detection of all semantic poisoning.** The detector matches a closed set of structural and
   lexical signals. Original, well-written steering text with no trigger phrase gets through — the
   project's own red-team review contains **ten worked examples** that landed ACTIVE
   (`docs/RED_TEAM_REVIEW.md`). The compensating control is provenance, not detection: every chunk
   from a weakly-trusted source is tagged `PROVENANCE:<tier>:treat_as_data_not_instructions`
   regardless of whether any rule fired, so a downstream policy can refuse to treat it as
   instruction. Raising `MF_MIN_RETRIEVAL_TRUST_TIER` excludes such sources entirely, at a
   measurable cost in recall.
2. **Broad factual contradiction detection.** The claim model governs exactly one typed domain
   (refund window by region and customer tier). Outside that schema there is no claim checking.
3. **Tamper-proofing.** A SHA-256 digest proves consistency with a separately stored expected value.
   It proves nothing about safety, and nothing at all against an attacker who controls both the
   content database and the manifest store. With `MF_HMAC_KEY` set, manifests are HMACs under a key
   held outside both files — better, still not tamper-proof.
4. **An immutable audit trail.** It is append-only *by construction of the application*. Someone
   with write access to the SQLite file can do as they please. "Application-level audit" is the
   accurate phrase and the one used throughout.
5. **Protection of memory outside this pipeline.** Only content routed through this API or SDK is
   covered.
6. **Valid time as an access control.** Scheduling content with a future `effective_from` does **not**
   hide it from someone who already holds the source ACL — asking "what will the policy be in
   December?" is a supported feature. If content must stay secret until a date, withhold the ACL or
   leave it in review. `MF_READERS_MAY_QUERY_FUTURE_VALID_TIME=0` restricts future-dated reads to
   reviewers, which narrows but does not eliminate this.
7. **Production readiness.** See below.
8. **100% of anything.** No percentage in this repository is a guarantee; every one is a measurement
   over a named synthetic dataset, reproducible with `make eval`.

---

## Security properties of the implementation

**Identity.** Bearer token only. `sha256(token)` is looked up in `principals`; the plaintext is never
stored. Unknown and disabled tokens return an identical message so the endpoint is not an oracle for
which tokens exist. There is no trusted header, no dev bypass, no `principal` query parameter.

**Request bodies.** Identity and privilege fields (`tenant_id`, `principal`, `role`, `trust_tier`,
`approved_by`, `state`, `token`, …) are stripped **before** validation — including from nested
objects and arrays — recorded as an audit event, and echoed back in `ignored_privileged_fields`.
`MF_STRICT_REJECT_FORGED_FIELDS=1` rejects such requests outright instead.

**Input bounds.** Document size cap, upload suffix allow-list (`.txt`, `.md`, `.json`), UTF-8-only
decoding, retrieval limit clamp, and `extra="forbid"` on every request model.

**Query handling.** User text is never interpolated into FTS5 query syntax. Alphanumeric tokens are
extracted, function words dropped, each remaining token emitted as a quoted phrase joined by `OR`.
`"); DROP TABLE chunks; --` becomes `"drop" OR "table" OR "chunks"`.

**No URL fetching anywhere.** There is no ingest-by-URL path, so there is no SSRF surface. A test
greps the engine and API for outbound-request calls and fails if one appears.

**Directory importer.** Root resolved once; every candidate resolved and required to remain inside
it; symlinked files *and* symlinked parents skipped; suffix allow-list; per-file size cap; dependency,
VCS and secret directories ignored.

**Untrusted previews.** A reviewer has to look at attacker-controlled text, so the preview path is an
injection surface. Two independent layers: the API serves a pre-escaped `preview_html` with invisible
characters rendered as visible `U+XXXX` tokens, and the dashboard **ignores it**, rebuilding
highlights from finding offsets using text nodes only. The dashboard never assigns `innerHTML`, and
is served with `default-src 'none'; script-src 'self'; style-src 'self'` — strict enough that it
blocked Playwright's own `wait_for_function`, which is how we know it is on.

**Binding.** Localhost by default, everywhere. The Docker images bind `0.0.0.0` *inside the
container* because that is the only way a container is reachable; `compose.yaml` publishes to
`127.0.0.1` on the host.

---

## Known weaknesses

Found by the project's own independent red-team review (`docs/RED_TEAM_REVIEW.md`) and kept here
because a weakness you can read is worth more than one you cannot.

| | Status |
|---|---|
| Unauthenticated demo-token disclosure in the dev adapter | **Fixed.** Both adapters now default the listing off, it is loopback-only, and `tests/integration/test_route_parity.py` asserts they cannot diverge again. |
| Readers could read not-yet-effective content via a future `as_of_valid` | **Documented and made configurable.** Not blocked by default: the release contract requires a reader to be able to ask about a future date. Results carry a `NOT_YET_IN_FORCE` tag. |
| Bypass suite did not exercise three live predicates | **Fixed.** Ten modes now, covering every predicate in the guarded query. |
| Original steering text evades the detector | **Open, by nature.** Ten worked examples published. Mitigated by provenance tagging and the optional trust floor, not by a claim to have fixed it. |

---

## The demo profile is not a deployment

`make setup` writes a `.env` with randomly generated local tokens and turns on two switches that
exist for the demo only:

- `MF_ENABLE_UNGUARDED_BASELINE=1` — the labelled measurement baseline endpoint (admin-only, and
  every response says it is not firewall output).
- `MF_DEV_EXPOSE_DEMO_TOKENS=1` — lets the dashboard list demo tokens so there is no login screen.
  **Off by default**, loopback-only, and never set by the Docker images.

Running `docker compose up` on localhost is a demonstration. Before anything resembling production
you would still need, at minimum:

- real authentication and credential lifecycle (these are static bearer tokens in a SQLite table);
- TLS, and a secret manager for `MF_HMAC_KEY`;
- a storage engine with backups, PITR and a concurrency story — SQLite WAL is right for a local
  single-process demo and is not a multi-writer database;
- rate limiting and request quotas (there are none);
- observability: metrics, structured logs, alerting on `fail_closed` and `integrity.alert` rates;
- a dependency and supply-chain review, and a threat review of *your* deployment;
- a data-retention policy — quarantined content is attacker-controlled text held indefinitely.

`docs/VERIFICATION.md` records what was actually executed, and what was not.
