# Threat model

**Scope.** Memory Firewall defends the memory layer of an agent or RAG system: what gets *written*
into durable memory, what gets *retrieved* out of it, and what is *handed* to a model. It is not an
application firewall, a model guardrail, or a replacement for the security of the agent itself.

---

## 1. What the attacker can do

The attacker is assumed able to:

| Capability | Example |
|---|---|
| Write to an untrusted or weakly-trusted source | comment on an issue, edit a shared wiki page, submit a feedback form |
| Poison a tool result | compromise or impersonate a third-party summariser whose output is ingested |
| Modify an untrusted source's content after it was indexed | edit their own comment later |
| Impersonate authority **in text** | write `trust_tier: authoritative_reviewed`, `approved_by: admin`, `System:` |
| Conceal instructions with encoding | zero-width characters, bidi overrides, homoglyphs, Unicode tag smuggling |
| Assert a contradictory fact | claim the refund window is 2 days when the authoritative policy says 30 |
| Supply arbitrary request fields | `{"tenant_id": "victim", "principal": "admin", "trust_tier": "..."}` |
| Supply hostile query text | FTS5 syntax, SQL fragments, enormous limits, extreme as-of timestamps |
| Supply hostile file content to the importer | path traversal, symlinks, oversized or binary files |

## 2. What the attacker cannot do

These are **assumptions**, not things this software enforces. If one is false, the corresponding
protection is void, and that is stated rather than hidden.

| Assumption | If it is false |
|---|---|
| Cannot obtain a reviewer or admin **bearer token** | identity is the token; the whole authorisation model collapses |
| Cannot write directly to the content database file | can set any state, though the manifest side-store still flags mutated text |
| Cannot write to the **manifest side-store** `<db>.manifests` | integrity detection is defeated entirely |
| Cannot modify the application's own code | every control is void |
| Cannot act as a trusted reviewer | content can be promoted into active memory by "approval" |

## 3. Trust tiers

Ordered weakest to strongest. A tier is **administrative state set by an admin and stored
server-side.** Nothing in a document's text can read or write it; the ingest path never accepts a
caller-supplied tier at all.

| Tier | Meaning | Typical source |
|---|---|---|
| `external_untrusted` | attacker-reachable; data, never instructions | issue comments, customer feedback, third-party tool results |
| `unreviewed_internal` | internal but unreviewed | scratch wiki pages, drafts |
| `reviewed_internal` | reviewed by a human, not authoritative | runbooks, internal guides |
| `authoritative_reviewed` | source of truth, reviewer-backed | the refund policy |
| `authoritative_signed` | as above, with tamper evidence via an HMAC manifest key held outside the DB | signed policy |

## 4. The three enforcement points

### 4.1 Pre-write

Hash → normalise → chunk → detect → extract typed claims → decide → persist, all in one
`BEGIN IMMEDIATE` transaction covering the content tables **and** the FTS index.

Normalisation is adversarial by design: invisible characters are removed, bidi controls removed,
confusables folded to ASCII, and Unicode tag characters **decoded rather than deleted** — deleting
them is exactly what ASCII-smuggling relies on. Every finding records a character span in the
**original** document so the evidence points at bytes the author actually wrote.

### 4.2 Pre-retrieval

One SQL statement. The gate is part of the search, not a filter over its results:

```
tenant match ∧ source.status='active' ∧ (source.expires_at IS NULL ∨ > as_of_valid)
  ∧ principal ∈ source_acl(read)
  ∧ document.status='active' ∧ chunk.state='active' ∧ version_validity.state='active'
  ∧ effective_from ≤ as_of_valid       ∧ (effective_to       IS NULL ∨ > as_of_valid)
  ∧ system_recorded_from ≤ as_of_recorded ∧ (system_recorded_to IS NULL ∨ > as_of_recorded)
  ∧ chunk_id ∈ fts_chunks MATCH query
```

then a trust-tier floor, then an integrity recheck against the side-store manifest. Each layer can
only *remove* rows. Any exception returns an empty, fail-closed result.

**Role does not bypass ACL.** An admin who is not in a source's read ACL does not receive its
content; the role grants authority over the system, not over every document.

### 4.3 At-use

A context pack carries chunk IDs, citations, trust tiers and risk tags. Chunks from
`external_untrusted` or `unreviewed_internal` are tagged
`PROVENANCE:<tier>:treat_as_data_not_instructions` **whether or not any rule fired**, because a
consumer cannot act on a detector limitation it cannot see. With no eligible evidence the pack is
empty, `insufficient_evidence` is true, and no answer is produced.

## 5. Write-decision matrix

Driven by the **unmitigated** maximum severity: a finding downgraded by the quotation mitigator
deliberately loses its power to block, but is still stored and still displayed.

| Unmitigated max severity | Source trust tier | Decision | Persisted state | Retrievable |
|---|---|---|---|---|
| none | `external_untrusted` | `ALLOW` | `active` | yes |
| none | `unreviewed_internal` | `ALLOW` | `active` | yes |
| none | `reviewed_internal` | `ALLOW` | `active` | yes |
| none | `authoritative_reviewed` | `ALLOW` | `active` | yes |
| none | `authoritative_signed` | `ALLOW` | `active` | yes |
| info | `external_untrusted` | `ALLOW_WITH_FLAGS` | `active` | yes |
| info | `unreviewed_internal` | `ALLOW_WITH_FLAGS` | `active` | yes |
| info | `reviewed_internal` | `ALLOW_WITH_FLAGS` | `active` | yes |
| info | `authoritative_reviewed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| info | `authoritative_signed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| low | `external_untrusted` | `ALLOW_WITH_FLAGS` | `active` | yes |
| low | `unreviewed_internal` | `ALLOW_WITH_FLAGS` | `active` | yes |
| low | `reviewed_internal` | `ALLOW_WITH_FLAGS` | `active` | yes |
| low | `authoritative_reviewed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| low | `authoritative_signed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| medium | `external_untrusted` | `REVIEW_REQUIRED` | `review_required` | no |
| medium | `unreviewed_internal` | `REVIEW_REQUIRED` | `review_required` | no |
| medium | `reviewed_internal` | `ALLOW_WITH_FLAGS` | `active` | yes |
| medium | `authoritative_reviewed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| medium | `authoritative_signed` | `ALLOW_WITH_FLAGS` | `active` | yes |
| high | `external_untrusted` | `QUARANTINE` | `quarantined` | no |
| high | `unreviewed_internal` | `QUARANTINE` | `quarantined` | no |
| high | `reviewed_internal` | `REVIEW_REQUIRED` | `review_required` | no |
| high | `authoritative_reviewed` | `REVIEW_REQUIRED` | `review_required` | no |
| high | `authoritative_signed` | `REVIEW_REQUIRED` | `review_required` | no |
| critical | `external_untrusted` | `QUARANTINE` | `quarantined` | no |
| critical | `unreviewed_internal` | `QUARANTINE` | `quarantined` | no |
| critical | `reviewed_internal` | `QUARANTINE` | `quarantined` | no |
| critical | `authoritative_reviewed` | `REVIEW_REQUIRED` | `review_required` | no |
| critical | `authoritative_signed` | `REVIEW_REQUIRED` | `review_required` | no |

| Current state | Reviewer decision | New state |
|---|---|---|
| `active` | `reject` | `rejected` |
| `active` | `revise` | `superseded` |
| `quarantined` | `approve` | `active` |
| `quarantined` | `reject` | `rejected` |
| `quarantined` | `revise` | `superseded` |
| `rejected` | `revise` | `superseded` |
| `review_required` | `approve` | `active` |
| `review_required` | `reject` | `rejected` |
| `review_required` | `revise` | `superseded` |

Any (state, decision) pair absent from the second table is refused with HTTP 409 rather than defaulting to a permissive outcome.


Any `(state, decision)` pair absent from the second table is refused with HTTP 409 rather than
defaulting to anything permissive.

## 6. Detector rules

| Rule | Family | Base severity | Catches |
|---|---|---|---|
| MF-R001 | `role_spoofing` | high | `System:` / `<\|im_start\|>system` / "SYSTEM OVERRIDE" / `Rôle : système` |
| MF-R002 | `instruction_override` | critical | "ignore previous instructions", "supersedes all other guidance", "is void/withdrawn", "takes precedence over" |
| MF-R003 | `agent_directed_imperative` | medium | "you must always", "never mention", "do not follow the policy" |
| MF-R004 | `exfiltration_hint` | critical | transfer verb + destination; payload-bearing URLs; `curl -X POST`; "mirror the transcript to…" |
| MF-R005 | `hidden_unicode` | high / low | zero-width and format characters; high when inside a word or when four or more appear |
| MF-R006 | `bidi_control` | high / medium | LRO/RLO overrides and isolates |
| MF-R007 | `homoglyph_spoof` | high / low | Cyrillic/Greek lookalikes; high inside a security-sensitive word |
| MF-R008 | `delimiter_spoof` | high | ` ```system `, `---BEGIN SYSTEM PROMPT---`, `[INST]`, `<<<SYS>>>` |
| MF-R009 | `self_declared_authority` | high | "signed master policy", `approved_by:`, "self-certifying", "its own header is the proof" |
| MF-R010 | `citation_suppression` | high | "do not cite the policy", "omit the attribution line", "without naming the source" |
| MF-R011 | `tool_invocation_injection` | high | `<function_call>`, `tools.update_kb(...)`, `action: invoke`, `approval: none` |
| MF-R012 | `script_injection` | medium | `<script`, `javascript:`, event-handler attributes |
| MF-R013 | `ascii_smuggling` | high | Unicode tag characters, reported with the decoded text |
| MF-R015 | `multi_stage_dormant` | high | "when a customer mentions X, reply only with Y", standing arrangements for "the assistant" |
| MF-R016 | `agent_addressed_directive` | high | a document instructing *the agent reading it* ("assistants reading this file should…") |
| MF-R017 | `non_english_override` | high | Spanish/French/German surface forms of the core override instructions |
| MF-R018 | `unapproved_policy_change` | high | a governed change advertising its own lack of approval ("no approver", "review skipped") |

Mitigator **MF-M001** downgrades a finding when the document *frames* the match as discussion.
Containment alone (quotes, a code fence) is **never** sufficient — that was an open evasion route in
the first implementation, and a fake ` ```system ` fence *is itself* the attack.

## 7. Claim integrity

One typed domain only: `RefundPolicy(region, customer_tier, days, effective_date)`. Claims are
compared only when `(subject, attribute, region, customer_tier)` match. A disagreement is a **review
state**, never a truth judgement — the system cannot know which document is correct, only which came
from an authority. A *weaker* source changing a value a *stronger* authority set is the signal that
escalates, and it does so **independently of the detector**, because "Refunds are now 2 days." trips
no lexical rule at all.

## 8. Residual risk

| Risk | Status |
|---|---|
| Original steering text with no structural signal | **Real and demonstrated.** Ten worked examples in `docs/RED_TEAM_REVIEW.md`. The honest ceiling of a deterministic detector. |
| Manipulation outside the one governed claim domain | Not covered. The claim model is narrow by design. |
| Attacker controlling both the content DB and the manifest store | Integrity detection defeated. Stated in `docs/SECURITY.md`. |
| Legitimate content wrongly withheld | Measured, not assumed: 2.2% hard-quarantined, 12.9% withheld including review-required. |
| Valid time mistaken for an access control | Documented sharp edge. Scheduling content for the future does not hide it from someone holding the ACL; `readers_may_query_future_valid_time=false` narrows it. |
| Languages beyond en/es/fr/de | Rule coverage is thin. No claim is made otherwise. |
| Adaptive adversary with the rule set in hand | Not evaluated. Would do better than these numbers. |
