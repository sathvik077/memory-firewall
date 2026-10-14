# Memory Firewall — Research Background, Prior Art, and Evaluation Design

Last literature verification pass: **2026-10-14**. Every URL below was fetched during that pass
unless explicitly annotated otherwise.

## 1. Scope and claim discipline

Memory Firewall is an **engineering and research integration contribution, not a discovery
claim**. It does not claim to have discovered memory poisoning, indirect prompt injection,
retrieval-time access-control bypass, or bitemporal data modelling: the attacks were
characterised in 2023–2025 literature, the defensive primitives are older, and the limits of
available mitigations are stated plainly by NIST and OWASP. What this project contributes is a
*specific, local-first, inspectable composition* of known primitives — server-assigned trust
tiers, deterministic pre-write scanning with stable rule IDs and evidence spans,
provenance-and-permission enforcement pushed **inside** the retrieval SQL, evidence-linked
context packs, and bitemporal replay of what was visible as-of a past valid time and a past
recorded time — plus a four-condition experiment on an identical corpus that makes the
composition's marginal value falsifiable. The hypothesis may turn out false, and Section 5 is
written so it can be shown false. This document makes **no claim that Memory Firewall is more
secure than, or competes with, any commercial product**; several systems below are broader,
better resourced, and operationally more mature.

## 2. Primary sources

### 2.1 AgentPoison — memory/knowledge-base backdoors in LLM agents

Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, Bo Li. *AgentPoison: Red-teaming LLM Agents
via Poisoning Memory or Knowledge Bases.* 38th Conference on Neural Information Processing
Systems (NeurIPS), 2024.
<https://proceedings.neurips.cc/paper_files/paper/2024/file/eb113910e9c3f6242541c1652e30dfd6-Paper-Conference.pdf>

Verified: the attack injects a few malicious demonstrations into an agent's long-term memory or
RAG corpus and optimises a trigger by constrained gradient-guided beam search so triggered
queries land in a compact region of the retriever's embedding space. It reports an average 81.2%
retrieval success rate and 62.6% end-to-end target attack success rate at a poison rate below
0.1%, with 0.74% average benign accuracy impact. Per-agent budgets go as low as 2 instances with
a 2-token trigger, and a single injected instance still averages 62% retrieval success. This
motivates treating **write admission** as a security boundary: corpus-size dilution arguments do
not hold at these budgets.

### 2.2 PoisonedRAG — knowledge corruption of RAG

Wei Zou, Runpeng Geng, Binghui Wang, Jinyuan Jia. *PoisonedRAG: Knowledge Corruption Attacks to
Retrieval-Augmented Generation of Large Language Models.* 34th USENIX Security Symposium, 2025.
<https://www.usenix.org/system/files/usenixsecurity25-zou-poisonedrag.pdf>

Verified: five crafted texts per target question, injected into databases of millions of clean
texts (2,681,468 for NQ), yield 0.88–0.97 black-box and 0.94–0.99 white-box attack success on
NQ, with comparable ranges on HotpotQA and MS-MARCO. Critically, all four evaluated defenses
proved insufficient: paraphrasing reduced but did not eliminate success (0.97 → 0.87 on NQ
black-box), perplexity detection could not separate malicious from clean text without flagging
many clean documents, duplicate filtering had no effect, and expanding retrieval to k=50 still
left roughly 41–43% success on HotpotQA. The authors conclude new defenses are needed — the
empirical basis for Memory Firewall's non-reliance on any single text-level screen.

### 2.3 OWASP RAG Security Cheat Sheet

OWASP Cheat Sheet Series. *RAG Security Cheat Sheet.* OWASP Foundation (living document; fetched
2026-10-14).
<https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html>

Verified: this document already prescribes most of Memory Firewall's architecture as recommended
practice — scanning incoming documents for hidden instructions, invisible Unicode and zero-width
characters before corpus entry; recording who uploaded each document, when, from where and under
what approval; keeping a signed or MAC-protected digest manifest while noting a digest match
shows baseline conformance and **not** safety; and storing access-control metadata on every
chunk rather than only the source document, re-evaluated when source permissions change. Its
central rule is "Enforce access control checks at retrieval time, not just at ingestion time,"
with permission filtering applied *before* similarity search. Memory Firewall is an
implementation and measurement of this guidance, not its originator.

### 2.4 OWASP LLM Prompt Injection Prevention Cheat Sheet

OWASP Cheat Sheet Series. *LLM Prompt Injection Prevention Cheat Sheet.* OWASP Foundation
(living document; fetched 2026-10-14).
<https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html>

Verified: the sheet separates direct injection from remote/indirect injection delivered via
retrieved documents, web pages, emails, code comments and commit messages, and states that
pattern-based filters do not reliably catch indirect injection. It presents keyword and regex
filters as illustrative rather than complete, warns that structured prompts separating
instructions from data help formatting but that **labels do not enforce a security boundary**,
and directs that permissions be enforced in execution code outside the model. It never claims
injection is solved, notes guardrail LLMs are themselves injectable, and says passing its smoke
test "does not show resistance to a persistent adversary." This bounds what Memory Firewall's
deterministic scanner may claim.

### 2.5 Agent Security Bench (ASB)

Hanrong Zhang, Jingyuan Huang, Kai Mei, Yifei Yao, Zhenting Wang, Chenlu Zhan, Hongwei Wang,
Yongfeng Zhang. *Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in
LLM-based Agents.* International Conference on Learning Representations (ICLR), 2025.
<https://proceedings.iclr.cc/paper_files/paper/2025/hash/5750f91d8fb9d5c02bd8ad2c3b44456b-Abstract-Conference.html>

Verified: ASB spans 10 scenarios, 10 agents, over 400 tools, 27 attack and defense methods and 7
metrics, covering 10 prompt-injection attacks, a memory poisoning attack, a Plan-of-Thought
backdoor, 4 mixed attacks and 11 defenses across 13 LLM backbones. The highest reported average
attack success rate is 84.30%, with vulnerabilities at distinct stages — system prompt, user
prompt handling, tool use and **memory retrieval** — and current defenses characterised as having
limited effectiveness. ASB's stage decomposition is the precedent for Memory Firewall's
write/retrieve/use split, and its utility-versus-security metric is the precedent for RQ2.

### 2.6 Google Cloud Model Armor

Google Cloud. *Model Armor overview.* Google Cloud documentation (living document; fetched
2026-10-14).
<https://docs.cloud.google.com/model-armor/overview>

Verified: Model Armor is a **managed** Google Cloud service, standalone or within Security
Command Center, screening both prompts and responses for responsible-AI categories, prompt
injection and jailbreak, sensitive data via Sensitive Data Protection, malicious URLs (first 256
per payload), and text in supported documents and images (image screening in Preview). It offers
*Inspect only* and *Inspect and block* modes, project-level floor settings imposing minimum
protections across templates, configurable templates with High / Medium-and-above /
Low-and-above thresholds, and integrations at Agent Gateway, Apigee, Gemini Enterprise, Google
Cloud MCP servers, networking services, Agent Platform and LangChain. It processes content
statelessly, evaluating each prompt and response independently without conversation history, and
does not decode encoded content. Its managed scale, model-boundary enforcement, multimodal
coverage and operational maturity are plainly broader than anything in this repository; the
documented statelessness is a different design point from a persistent memory ledger, not a
deficiency.

### 2.7 Microsoft — defending against indirect prompt injection

Microsoft. *Defend against indirect prompt injection attacks.* Microsoft Learn, Secure Future
Initiative / Zero Trust guidance (living document; fetched 2026-10-14).
<https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection>

Verified: Microsoft describes ten layered mitigations — prompt shields, spotlighting (data
marking and metaprompting), plan drift detection, critic agents, tool chain analysis, in-skill
security guardrails, **information flow control enforcing policy-based isolation of untrusted
content using metadata and quarantined inference environments**, least privilege, short-lived
privileges, and human-in-the-loop verification — explicitly layering probabilistic and
deterministic controls. The guidance states "Assume indirect prompt injection will happen,"
"Design systems with the expectation that some attacks will succeed," and "No single solution is
sufficient," framing the objective as containing impact rather than preventing injection. Memory
Firewall's trust tiers, quarantine state and risk-tagged context packs are an instance of the
IFC-with-metadata layer Microsoft names, not an alternative to it.

### 2.8 Greshake et al. — indirect prompt injection in deployed applications

Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz.
*Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect
Prompt Injection.* arXiv:2302.12173v2, 2023 (v1 2023-02-23; v2 2023-05-05).
<https://arxiv.org/abs/2302.12173v2>

Verified: LLM-integrated applications blur the boundary between data and instructions, so an
attacker need not type a malicious prompt — planting instructions in content the application will
retrieve suffices, after which the model treats them as operator-originated. The authors present
a computer-security taxonomy covering data theft, worming (self-propagating injections),
contamination of the information ecosystem and further novel risks, demonstrated against real
systems including Bing's GPT-4-powered chat and code-completion engines, and observe that
injected prompts can behave like arbitrary code execution controlling whether and how other APIs
are invoked. They report that effective mitigations are lacking. *Venue note:* this work is widely
cited as appearing at ACM AISec '23, but the arXiv landing page lists no venue and the
proceedings entry could not be confirmed from this environment on 2026-10-14 (dblp returned
`ROBOTS_DISALLOWED`), so it is cited here as the verified arXiv preprint.

### 2.9 CaMeL — Defeating Prompt Injections by Design

Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian,
Christoph Kern, Chongyang Shi, Andreas Terzis, Florian Tramèr. *Defeating Prompt Injections by
Design.* arXiv:2503.18813, 2025 (v1 2025-03-24; v2 2025-06-24).
<https://arxiv.org/abs/2503.18813>

Verified: CaMeL wraps an LLM agent in a protective system layer so the system stays secure even
when the model is injectable, deriving control flow and data flow from the *trusted user query*
so untrusted data retrieved during execution cannot alter what the program does. It attaches
capabilities to data values and enforces security policies at tool-call time to block
unauthorized exfiltration flows, solving 77% of AgentDojo tasks with provable security against
84% for an undefended system. This is the strongest counterpoint to Memory Firewall's design:
CaMeL offers a *provable* guarantee at the planning/tool layer that trust tiers and
retrieval-time filtering do not. The two are complementary — CaMeL constrains what retrieved data
can *do*, Memory Firewall constrains what reaches retrieval and records why — and any claim that
memory-layer filtering substitutes for a flow-control guarantee would be unsupported.

### 2.10 NIST adversarial ML taxonomy

Apostol Vassilev, Alina Oprea, Alie Fordyce, Hyrum Anderson, Xander Davies, Maia Hamin.
*Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations.*
NIST AI 100-2e2025, National Institute of Standards and Technology, U.S. Department of Commerce,
March 2025.
<https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-2e2025.pdf>

Verified: the report taxonomises attacks by violated property — availability, integrity, privacy
and misuse — indexing data poisoning under availability, integrity and privacy violations, with a
dedicated supply-chain section covering data and model poisoning and a dedicated indirect
prompt-injection section spanning availability, integrity and privacy compromise; the
introduction notes that RAG and LLM agents broaden the attack surface. On mitigations it is
deliberately sober: available defenses "tend to be empirical and limited in nature," are often
adopted because they appear to work rather than because they offer formal guarantees, and "may
themselves be vulnerable to new discoveries and evolutions in attacker techniques," with
information-theoretic impossibility results bounding some widely used techniques. Memory
Firewall's claims are scoped to match this posture.

### 2.11 OWASP Top 10 for LLM Applications 2025

OWASP Gen AI Security Project. *OWASP Top 10 for Large Language Model Applications, 2025
edition.* OWASP Foundation (fetched 2026-10-14).
<https://genai.owasp.org/llm-top-10/>

Verified: the 2025 list is LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03
Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive
Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation,
LLM10 Unbounded Consumption. LLM04 explicitly covers poisoning of data used in pre-training,
fine-tuning *or embeddings*; LLM08 covers risks arising from vulnerabilities in vectors and
embeddings within the systems that use them. Memory Firewall's threat surface is therefore
pre-existing, named and ranked industry risk. (The landing page served truncated teasers per
entry, so only the IDs, names and teaser-level descriptions are asserted here.)

### 2.12 Bitemporal tables in the SQL standard

Krishna Kulkarni, Jan-Eike Michels. *Temporal Features in SQL:2011.* ACM SIGMOD Record,
41(3):34–43, 2012. DOI 10.1145/2380776.2380786.
<https://sigmodrecord.org/2012/09/30/temporal-features-in-sql2011/>

Verified: SQL:2011 standardises application-time period tables (valid time, via `PERIOD FOR`,
with automatic period splitting on update/delete, `WITHOUT OVERLAPS` temporal primary keys and
temporal referential integrity), system-versioned tables (transaction time, via
`PERIOD FOR SYSTEM_TIME ... WITH SYSTEM VERSIONING`, engine-maintained), **bitemporal tables
combining both**, and time-sliced retrieval via `AS OF SYSTEM TIME` and
`VERSIONS BETWEEN SYSTEM TIME`. Memory Firewall's "time machine" is this standard model applied
to a memory ledger; the two-axis separation of valid time from recorded time is fourteen years
old in the standard and older in the research literature. *Verification note:* the SIGMOD Record
landing page and the Crossref record (vol. 41, no. 3, pp. 34–43, 2012) were both fetched
successfully, but the article PDF mirror returned a client error on 2026-10-14, so the feature
description is taken from the published SQL:2011 standard summary rather than the article body.

## 3. Honest comparison matrix

| System / work | Enforcement point(s) | Detection vs prevention | Provenance & versioning | Multi-session memory replay | Open-source & local-first | What Memory Firewall adds that is testable |
| --- | --- | --- | --- | --- | --- | --- |
| AgentPoison (NeurIPS 2024) | None — offensive red-teaming of memory/KB | Neither; establishes feasibility at <0.1% poison rate | n/a | n/a | Research artifact, code released | A defender-side pipeline measured against this attack class, reporting poison-reaching-context rate rather than attack success alone |
| PoisonedRAG (USENIX Sec 2025) | None — offensive; evaluates 4 candidate defenses | Shows perplexity, dedup, paraphrase and expansion all insufficient | n/a | n/a | Research artifact, code released | Tests whether admission control *plus* retrieval-time eligibility changes the picture where four text-level defenses did not |
| OWASP RAG Security Cheat Sheet | Prescribes ingestion, retrieval and index-integrity controls | Prescriptive guidance, not an implementation | Prescribes upload provenance, signed digest manifests, per-chunk ACLs, permission re-evaluation | Not addressed | Documentation (CC-licensed) | A runnable reference implementation with stable per-rule IDs and an experiment quantifying each layer's marginal effect |
| OWASP Prompt Injection Prevention Cheat Sheet | Input, prompt structure, privilege, output | States pattern filters miss indirect injection; defense-in-depth | Not the focus | Not addressed | Documentation (CC-licensed) | A deterministic rule set with character-level evidence spans, measured for precision/recall rather than asserted |
| Agent Security Bench (ICLR 2025) | Benchmark harness across prompt, tool and memory stages | Measures both; finds 11 defenses of limited effectiveness | Not a provenance system | Memory poisoning attack, but no as-of replay | Research artifact, code released | Bitemporal exposure replay and a reviewer-approval axis absent from ASB's defense set |
| Google Cloud Model Armor | Prompt/response screening at gateway and platform integration points; project floor settings | Prevention-capable (Inspect and block) plus Inspect-only detection; managed, tunable thresholds | Not a corpus provenance ledger; stateless per call by design | No — each prompt/response evaluated independently, no conversation history | No — managed cloud service | Nothing comparable in scale, multimodal coverage or operational maturity. Model Armor is broader and better integrated at the model boundary; Memory Firewall occupies a different layer — durable per-chunk provenance and as-of replay |
| Microsoft indirect-injection guidance | Ten layers incl. prompt shields, spotlighting, plan drift, critic agents, tool chain analysis, IFC, least/short-lived privilege, HITL | Explicitly assumes some attacks succeed; containment-oriented | IFC with metadata and quarantined inference environments | Not specified as temporal replay | Documentation; products commercial | A concrete, inspectable instantiation of the IFC-with-metadata layer, with the quarantine decision and its evidence auditable offline |
| Greshake et al. (2023) | None — offensive taxonomy | Neither; characterises data/instruction boundary collapse | n/a | n/a | Preprint | Operationalises that boundary as a server-assigned trust tier document text cannot change, and tests the invariant |
| CaMeL (2025) | Planner / tool-call layer | Prevention with a provable guarantee for completed tasks (77% vs 84% undefended on AgentDojo) | Capabilities attached to data values; not corpus versioning | No | Research artifact, code released | Complementary and a strictly weaker guarantee class: CaMeL constrains what retrieved data can do; Memory Firewall constrains what enters, what is retrievable, and records why |
| NIST AI 100-2e2025 | Taxonomy, not enforcement | States mitigations are empirical and limited | n/a | n/a | Public-domain publication | An artifact evaluated in the sober posture NIST recommends, reporting failure cases rather than coverage claims |
| OWASP Top 10 for LLMs 2025 | Risk taxonomy (LLM01, LLM04, LLM08) | Risk register, not enforcement | n/a | n/a | Documentation (CC-licensed) | A mapping from LLM01/LLM04/LLM08 to concrete enforcement points with measured residual exposure |
| SQL:2011 temporal tables (Kulkarni & Michels) | Database layer | Neither; a data model | Valid time + system time, bitemporal, `AS OF` queries | Standardised as-of queries over table state | Standard; implemented in several open engines | Applies the standard bitemporal model to an evidence-linked memory ledger and measures whether as-of replay reduces stale-policy conflicts (RQ3) |

## 4. Where Memory Firewall is NOT novel

Memory Firewall reuses, without claim of originality:

- **Access control lists and tenant isolation**, including per-chunk rather than per-document
  ACLs and permission filtering applied before similarity ranking — OWASP RAG cheat sheet.
- **Content scanning for hidden instructions**, invisible Unicode, zero-width characters,
  homoglyphs and bidi controls — same cheat sheet; its limits are stated in the OWASP
  prompt-injection cheat sheet and demonstrated by PoisonedRAG's perplexity result.
- **Signed/MAC-protected integrity manifests**, with the caveat that digest match proves baseline
  conformance and not safety — OWASP RAG cheat sheet.
- **Quarantine as a pipeline state** for untrusted or unreviewed content, and quarantined
  inference environments — Microsoft's IFC layer.
- **Information-flow control with trust metadata**, least privilege, and privilege separation
  between the model and the enforcement code — Microsoft guidance, OWASP, and in a stronger
  provable form CaMeL.
- **Bitemporal temporal tables** (valid time and system/transaction time) and `AS OF` time-sliced
  queries — SQL:2011, standardised in 2011, described by Kulkarni & Michels in 2012.
- **Reviewer/approval workflows with audit trails**, and recording who uploaded what, when, from
  where and under what approval — OWASP RAG cheat sheet.
- **Stage-decomposed security evaluation of agent pipelines** — Agent Security Bench.
- **Fail-safe abstention when no eligible evidence exists** — standard grounded-QA practice,
  consistent with OWASP's human-in-the-loop and output-handling guidance.

The composition, the local-first SQLite/FTS5 implementation, the stable rule-ID-plus-evidence-span
reporting format, and the four-condition marginal-value experiment are offered as new
*engineering integration*, not as discovery.

## 5. Research questions and null hypotheses

All four conditions run over an **identical corpus** and query set: (i) naive unguarded FTS
retrieval, (ii) keyword-only text screening, (iii) write-only firewall, (iv) write + retrieve +
provenance/ACL firewall (dual-gate). Denominators are fixed before running, and the held-out
perturbation split is not inspected during rule development.

### RQ1 — Poison reaching answer context

What fraction of injected poison reaches answer context under naive, keyword-only, write-only and
dual-gate pipelines?

- **H0(1):** the poison-reaching-context rate is equal across all four conditions; in particular
  the dual-gate condition does not differ from write-only.
- **Falsifying metric:** per-condition *poison exposure rate* = (attack queries whose emitted
  context pack contains at least one chunk derived from an injected poison document) / (attack
  queries), with exact binomial intervals and paired per-query comparison. H0 is rejected only if
  the dual-gate interval excludes the write-only point estimate on **both** the development and
  the held-out perturbation split. Secondary metric: *propagation depth* — whether a retrieved
  poisoned chunk is also cited in the answer.

### RQ2 — Benign context lost as scanner aggressiveness rises

How much benign relevant context is lost as scanner aggressiveness increases?

- **H0(2):** increasing scanner aggressiveness does not reduce benign retrieval recall@k — the
  utility cost of stricter screening is zero.
- **Falsifying metric:** benign **recall@k** and answer-utility rate at each threshold setting,
  paired with *false quarantine rate* = (benign documents quarantined) / (benign documents
  submitted). A monotone decreasing recall@k curve with non-overlapping intervals between the
  loosest and strictest settings falsifies H0. The reported artifact is a full confusion matrix
  (true/false quarantine, true/false admit) per threshold plus detection precision and recall —
  not a single headline accuracy figure.

### RQ3 — Reviewer-approved provenance and versioning vs stale-policy conflicts

Does reviewer-approved provenance plus versioning reduce stale-policy conflicts in the typed
structured-claim domain (refund policy: region, customer tier, days, effective date)?

- **H0(3):** the stale-policy answer rate is equal with and without reviewer-approval state and
  bitemporal version filtering; provenance metadata carries no measurable effect.
- **Falsifying metric:** *stale-claim answer rate* = (queries answered from a structured claim
  superseded as of the query's valid time) / (queries over the conflict set), with version
  filtering on versus off, reported separately for as-of-valid-time and as-of-recorded-time
  replays. A paired difference whose interval excludes zero falsifies H0. Secondary check:
  *citation correctness* — whether the cited chunk's version is the one in force at the asserted
  valid time.

### RQ4 — Additional local latency of end-to-end protection

What additional local latency does end-to-end protection add?

- **H0(4):** the dual-gate pipeline's ingestion and retrieval latency distributions are
  indistinguishable from the naive pipeline's.
- **Falsifying metric:** p50 and p95 ingestion overhead and retrieval latency per condition over a
  fixed repetition count on one documented local machine, with machine specification and corpus
  size recorded alongside, plus approximate memory and storage cost. A p95 difference exceeding
  measurement noise falsifies H0. Latency results are descriptive and machine-specific, and are
  explicitly not generalised (Section 6).

## Measured results

<!-- RESULTS_PLACEHOLDER: filled from evals/RESULTS.md after make eval -->

## 6. Threats to validity

1. **Synthetic, single-domain dataset.** The corpus is synthetic and centred on one
   support/refund-policy domain. Effect sizes here say nothing about multi-domain corpora, real
   enterprise document heterogeneity, or the millions-of-documents scale at which PoisonedRAG
   operated. External validity is low by construction.
2. **Author-written attacks and overfitting risk.** The attack set is written by the same authors
   who wrote the detection rules, risking rules that fit the attacks rather than the attack class.
   Mitigation: a **held-out perturbation split** generated after rule freeze and never inspected
   during rule development, with development-split results reported separately from and
   subordinate to held-out results. This reduces but does not remove shared-authorship bias,
   since both splits inherit one team's threat intuitions.
3. **Lexical detector ceiling.** The pre-write scanner is deterministic and largely lexical and
   structural. OWASP states directly that pattern-based filters do not reliably catch indirect
   injection, and PoisonedRAG showed perplexity-based separation fails without heavy
   false-positive cost. Semantically paraphrased, multilingual, encoding-obfuscated,
   image-embedded or cross-chunk-split injections are expected to pass; such cases belong in the
   qualitative failure-case appendix, and detection recall must not be read as coverage.
4. **No frontier-model adversary.** Attacks are not generated by an optimisation loop against the
   deployed retriever, unlike AgentPoison's gradient-guided trigger search, nor adaptively by a
   frontier model with knowledge of the rule set. Measured exposure rates are therefore **upper
   bounds on defense effectiveness** against a static adversary; an adaptive adversary should be
   assumed to do better.
5. **Non-generalizable latency numbers.** Latency and storage figures come from a small local
   corpus on one machine with SQLite FTS5. They do not predict behaviour under concurrent load,
   larger indexes, different storage media or vector-index backends, and must not be read as a
   performance comparison against any managed service.
6. **Enforcement scope.** Memory Firewall guards write, retrieve and use within the memory/RAG
   path only. It does not constrain the planner or tool-call layer, so it offers no guarantee of
   the kind CaMeL provides, and it does not address model-weight poisoning, supply-chain
   compromise of the retriever, or injection arriving through channels that bypass the memory path
   entirely. Consistent with NIST AI 100-2e2025 and Microsoft's guidance, some attacks are assumed
   to succeed; the design goal is bounded, explainable, auditable containment.
