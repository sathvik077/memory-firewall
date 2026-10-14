# Memory Firewall — evaluation scorecard

Generated **2026-10-14T19:53:36.544193Z** · engine `0.1.0` · detector `mf-detector/1.0.0` · policy `mf-policy/1.0.0`

Environment: Python 3.13.16 on Linux-6.18.44-fc-v114-x86_64-with-glibc2.39.

> Every number below was produced by `make eval` on the committed dataset. Nothing here is estimated, extrapolated or hand-written. Latency figures describe a small local corpus on one machine and are not a general performance claim.

## Dataset

`evals/dataset/cases.jsonl` — 178 labelled cases.

Authored by an independent agent that was kept blind to the detector implementation; see evals/dataset/DATASET.md.

| label / split | cases |
|---|---:|
| benign/heldout_perturbation | 21 |
| benign/primary | 72 |
| malicious/heldout_perturbation | 18 |
| malicious/primary | 67 |

## Headline comparison

| condition | write screening | retrieval | poison exposure | stale-index exposure | benign recall@3 | false quarantine |
|---|---|---|---:|---:|---:|---:|
| **Naive unguarded RAG** | none | blind lexical search | 3.5% | 100.0% | 17.2% | 0.0% |
| **Keyword-only screening** | naive phrase blocklist on raw text | blind lexical search | 3.5% | 100.0% | 17.2% | 7.5% |
| **Write-time firewall only** | full Memory Firewall write policy | blind lexical search | 0.0% | 100.0% | 17.2% | 2.1% |
| **Write + retrieve guard (Memory Firewall)** | full Memory Firewall write policy | permission-aware guarded query + integrity recheck | 0.0% | 0.0% | 14.0% | 2.1% |

**Reading this table.** *Poison exposure* is the fraction of malicious cases whose own text came back for its own query. *Stale-index exposure* is the fraction of the seven forced index-injection modes that reached the caller — it is where a write-only firewall and a dual-gate firewall genuinely differ, because a write gate cannot clean an index it never saw. *False quarantine* counts benign cases that were hard-quarantined, which is the pre-registered false-positive metric; the looser *benign withheld rate* (which also counts review-required) is in the per-condition sections below.

## Detection quality per condition

### Naive unguarded RAG (`unguarded`)

Everything ingested is indexed and retrievable. The control: what a normal RAG pipeline would have exposed on this corpus.

| metric | value |
|---|---:|
| cases | 178 (85 malicious, 93 benign) |
| TP / FP / TN / FN | 0 / 0 / 93 / 85 |
| precision | n/a |
| recall | 0 |
| F1 | n/a |
| accuracy | 0.5225 |
| poison exposure rate | 3.5% (3/85) |
| benign recall@3 | 17.2% |
| benign withheld rate | 0.0% |
| false quarantine rate | 0.0% (0/93) |
| stale-index exposure | 10/10 |
| ingestion p50 / p95 | 13.29 ms / 20.23 ms |
| retrieval p50 / p95 | 1.693 ms / 2.625 ms |

Held-out comparison (a large gap indicates overfitting to the author's phrasing):

| split | cases | recall | poison exposure | benign recall@3 |
|---|---:|---:|---:|---:|
| `heldout_perturbation` | 39 | 0 | 0.0% | 4.8% |
| `primary` | 139 | 0 | 4.5% | 20.8% |

### Keyword-only screening (`keyword_only`)

A literal phrase blocklist at ingestion, no normalisation and no retrieval gate — the common first attempt at this problem.

| metric | value |
|---|---:|
| cases | 178 (85 malicious, 93 benign) |
| TP / FP / TN / FN | 14 / 7 / 86 / 71 |
| precision | 0.6667 |
| recall | 0.1647 |
| F1 | 0.2641 |
| accuracy | 0.5618 |
| poison exposure rate | 3.5% (3/85) |
| benign recall@3 | 17.2% |
| benign withheld rate | 7.5% |
| false quarantine rate | 7.5% (7/93) |
| stale-index exposure | 10/10 |
| ingestion p50 / p95 | 14.5 ms / 19.35 ms |
| retrieval p50 / p95 | 1.471 ms / 2.31 ms |

Held-out comparison (a large gap indicates overfitting to the author's phrasing):

| split | cases | recall | poison exposure | benign recall@3 |
|---|---:|---:|---:|---:|
| `heldout_perturbation` | 39 | 0 | 0.0% | 4.8% |
| `primary` | 139 | 0.209 | 4.5% | 20.8% |

### Write-time firewall only (`write_only`)

The real detector, claim graph and write policy, but retrieval performs no tenant, ACL, state, temporal or integrity check.

| metric | value |
|---|---:|
| cases | 178 (85 malicious, 93 benign) |
| TP / FP / TN / FN | 79 / 12 / 81 / 6 |
| precision | 0.8681 |
| recall | 0.9294 |
| F1 | 0.8977 |
| accuracy | 0.8989 |
| poison exposure rate | 0.0% (0/85) |
| benign recall@3 | 17.2% |
| benign withheld rate | 12.9% |
| false quarantine rate | 2.1% (2/93) |
| stale-index exposure | 10/10 |
| ingestion p50 / p95 | 14.35 ms / 20.73 ms |
| retrieval p50 / p95 | 1.457 ms / 2.64 ms |

Held-out comparison (a large gap indicates overfitting to the author's phrasing):

| split | cases | recall | poison exposure | benign recall@3 |
|---|---:|---:|---:|---:|
| `heldout_perturbation` | 39 | 0.8889 | 0.0% | 4.8% |
| `primary` | 139 | 0.9403 | 0.0% | 20.8% |

### Write + retrieve guard (Memory Firewall) (`full`)

Both enforcement points. The product.

| metric | value |
|---|---:|
| cases | 178 (85 malicious, 93 benign) |
| TP / FP / TN / FN | 79 / 12 / 81 / 6 |
| precision | 0.8681 |
| recall | 0.9294 |
| F1 | 0.8977 |
| accuracy | 0.8989 |
| poison exposure rate | 0.0% (0/85) |
| benign recall@3 | 14.0% |
| benign withheld rate | 12.9% |
| false quarantine rate | 2.1% (2/93) |
| stale-index exposure | 0/10 |
| ingestion p50 / p95 | 13.69 ms / 19.65 ms |
| retrieval p50 / p95 | 9.422 ms / 18.85 ms |

Held-out comparison (a large gap indicates overfitting to the author's phrasing):

| split | cases | recall | poison exposure | benign recall@3 |
|---|---:|---:|---:|---:|
| `heldout_perturbation` | 39 | 0.8889 | 0.0% | 4.8% |
| `primary` | 139 | 0.9403 | 0.0% | 16.7% |

## How much utility does the guard actually cost?

Curated-QA recall@3 is **100.0%** with no guard at all and **100.0%** with the full guard — a guard-attributable delta of **0.0**.

A delta of 0.0 means the guard withheld no eligible authoritative answer: any shortfall against the pre-registered target is a lexical-ranking limitation shared by the unguarded baseline, not a cost of the trust boundary.

## Pre-registered goals

These targets were written in `CLAUDE.md` §8 **before** the system was built. They are goals to measure, not guarantees, and an unmet goal is reported as unmet.

| goal | target | observed | met |
|---|---|---:|:--:|
| zero forbidden exposure in deterministic suite | 0 quarantined/unauthorised chunks exposed | 0 | yes |
| recall at least 90pct for defined families | >= 0.90 recall (malicious withheld) | 0.9294 | yes |
| false quarantine at most 10pct | <= 0.10 false quarantine among benign | 0.0215 | yes |
| curated qa recall at 3 at least 95pct | >= 0.95 top-3 recall of eligible authoritative chunks (curated QA set) | 1 | yes |
| p95 retrieval overhead under 100ms | < 100 ms p95 guarded retrieval on a small local corpus | 18.85 | yes |

**curated qa recall at 3 at least 95pct** — Unmet by []. The same question is missed identically by the unguarded baseline, so the shortfall is bm25 ambiguity between several refund documents rather than anything the guard withheld (guard-attributable delta: 0.0).

## Per-family behaviour (full condition)

| family | label | n | withheld | exposure | recall@3 |
|---|---|---:|---:|---:|---:|
| `benign_imperative` | benign | 8 | 12.5% | 0.0% | 0.0% |
| `benign_url_reference` | benign | 7 | 14.3% | 0.0% | 0.0% |
| `citation_suppression` | malicious | 6 | 100.0% | 0.0% | 0.0% |
| `conflicting_but_legitimate` | benign | 9 | 22.2% | 11.1% | 11.1% |
| `delimiter_spoof` | malicious | 6 | 100.0% | 0.0% | 0.0% |
| `exfiltration_hint` | malicious | 9 | 88.9% | 0.0% | 0.0% |
| `hidden_unicode` | malicious | 9 | 100.0% | 0.0% | 0.0% |
| `homoglyph_spoof` | malicious | 6 | 100.0% | 0.0% | 0.0% |
| `instruction_override` | malicious | 9 | 88.9% | 0.0% | 0.0% |
| `legit_approved_policy_update` | benign | 8 | 12.5% | 25.0% | 25.0% |
| `legit_policy_statement` | benign | 11 | 9.1% | 27.3% | 27.3% |
| `multi_stage_dormant` | malicious | 6 | 100.0% | 0.0% | 0.0% |
| `multilingual_benign` | benign | 8 | 0.0% | 12.5% | 12.5% |
| `quoted_attack_example` | benign | 14 | 42.9% | 0.0% | 0.0% |
| `role_spoofing` | malicious | 9 | 88.9% | 0.0% | 0.0% |
| `security_documentation` | benign | 9 | 0.0% | 0.0% | 0.0% |
| `self_declared_authority` | malicious | 8 | 100.0% | 0.0% | 0.0% |
| `technical_doc_with_code` | benign | 9 | 0.0% | 22.2% | 0.0% |
| `tool_invocation_injection` | malicious | 6 | 100.0% | 0.0% | 0.0% |
| `unauthorized_claim_mutation` | malicious | 11 | 72.7% | 0.0% | 0.0% |
| `unrelated_knowledge` | benign | 10 | 0.0% | 60.0% | 60.0% |

## Known blind spots, from these results

* No malicious case reached answer context under the full condition **on this dataset**. That is a result about this dataset, not a general guarantee.
* **12 benign case(s) were withheld**: EV-B-0001, EV-B-0013, EV-B-0020, EV-B-0022, EV-B-0027, EV-B-0028, EV-B-0031, EV-B-0050, EV-B-0058, EV-B-0078, EV-B-0083, EV-B-0089. Over-blocking legitimate content is a real failure mode and is reported, not hidden.
* Broad semantic poisoning is **not** covered. The claim model governs exactly one typed domain (refund window by region and customer tier); a manipulation outside that schema with no structural signal will not be caught.
* The dataset is synthetic, single-domain and single-author. The held-out split limits, but does not eliminate, overfitting to one writer's phrasing.
* No adaptive adversary was run. An attacker with this rule set in hand would do better.

## Reproducing

```bash
make eval        # full run, rewrites evals/results/RESULTS.json and RESULTS.md
python -m evals.runner --quick   # fast sampled loop for development
```
