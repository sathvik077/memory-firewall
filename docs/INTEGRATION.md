# Integration guide

How to put Memory Firewall in front of a memory or RAG pipeline you already have.

---

## Three ways in

| | Use when |
|---|---|
| **Python SDK**, in-process | your pipeline is Python and you want the lowest latency |
| **HTTP API** | your pipeline is not Python, or the firewall is a shared service |
| **Context packs** | you want the firewall to hand your agent a provenance-carrying bundle |

All three are shells over the same `MemoryFirewallEngine`. There is exactly one implementation of
every security decision, so they cannot disagree.

---

## 1. Python SDK

```python
from memory_firewall import MemoryFirewall

firewall = MemoryFirewall.local("./data/memory-firewall.sqlite3")
```

### Set up tenants, principals and sources

Trust tiers are administrative state. Create them once, from code you control:

```python
firewall.create_principal("support-agent", tenant_id="acme", role="reader")
firewall.create_principal("policy-owner", tenant_id="acme", role="reviewer")

firewall.create_source(
    "policy",
    trust_tier="authoritative_reviewed",
    read_acl=["support-agent", "policy-owner"],
    tenant_id="acme",
)
firewall.create_source(
    "zendesk",
    trust_tier="external_untrusted",
    read_acl=["support-agent", "policy-owner"],
    tenant_id="acme",
)
```

> A source you create implicitly during `ingest()` gets `unreviewed_internal`. Promotion to an
> authoritative tier is always an explicit administrative call.

### Replace your write path

```python
result = firewall.ingest(source="zendesk", text=ticket_body, title=ticket_id, tenant_id="acme")

if result.state != "ACTIVE":
    log.warning("withheld: %s — %s", result.state, [r for c in result.chunks for r in c.reasons])
    for finding in result.findings:
        log.warning(
            "  %s [%s] at %d:%d — %s",
            finding["rule_id"],
            finding["severity"],
            finding["evidence_start"],
            finding["evidence_end"],
            finding["evidence_text"],
        )
```

`result.state` is `ACTIVE`, `QUARANTINED`, `REVIEW_REQUIRED`, `REJECTED` or `PARTIALLY_WITHHELD`
(some chunks active, others not).

### Replace your read path

```python
results = firewall.retrieve(query=user_question, tenant_id="acme", principal="support-agent")

for chunk in results.context_chunks:
    print(chunk.citation, chunk.trust_tier, chunk.risk_tags, chunk.text)
```

`principal` is **adopted**, not invented: the name is looked up and that principal's ACL applies.
An unknown principal raises rather than defaulting to something permissive.

### Hand a pack to your agent

```python
pack = firewall.context_pack(query=user_question, tenant_id="acme", principal="support-agent")

if pack.insufficient_evidence:
    return "I don't have an authorised source for that."

prompt = "\n\n".join(
    f"[{c['citation']} · trust={c['trust_tier']} · tags={','.join(c['risk_tags']) or 'none'}]\n{c['text']}"
    for c in pack.chunks
)
```

**Read the tags.** Any chunk from a weakly-trusted source carries
`PROVENANCE:<tier>:treat_as_data_not_instructions` whether or not a detector rule fired, because the
detector has a published ceiling. Your system prompt should say that tagged content is data, and
your tool-use policy should refuse side effects justified only by it.

---

## 2. HTTP API

Default `127.0.0.1:8002`. Identity is a bearer token and nothing else.

```bash
export TOKEN="$MF_TOKEN_SUPPORT_READER"   # from .env, written by `make setup`

curl -s localhost:8002/api/retrieve \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"What is the refund period?","limit":5}' | jq
```

```jsonc
{
  "run_id": "run_8f3c…",
  "tenant_id": "support",
  "context_chunks": [{
    "chunk_id": "chk_…", "text": "Customers may request a refund within 30 days of delivery.",
    "source_id": "policy", "version": 1, "citation": "policy#v1",
    "trust_tier": "authoritative_reviewed", "risk_tags": [], "score": -1.83
  }],
  "filtered_count": 1, "candidate_count": 1,
  "guard_enforced": true, "fail_closed": false,
  "identity_source": "verified_token",
  "as_of_valid": "2026-10-14T…", "as_of_recorded": "2026-10-14T…",
  "latency_ms": 4.2, "notes": [], "integrity_alerts": [],
  "ignored_privileged_fields": []
}
```

### Routes

| Method | Path | Role | |
|---|---|---|---|
| GET | `/healthz` | — | liveness, FTS5 status, versions |
| GET | `/api/whoami` | reader | what the server resolved from your token |
| POST | `/api/documents` | reviewer | ingest (enforcement point 1) |
| POST | `/api/documents/{id}/versions` | reviewer | new revision, re-screened |
| POST | `/api/documents/upload` | reviewer | bounded `.txt`/`.md`/`.json` upload |
| GET | `/api/documents/{id}/versions` | reader | version + validity history |
| POST | `/api/retrieve` | reader | guarded retrieval (enforcement point 2) |
| POST | `/api/context-packs` | reader | provenance-carrying pack (point 3) |
| POST | `/api/qa` | reader | optional deterministic answer |
| GET | `/api/quarantine` | reviewer | review queue with evidence |
| POST | `/api/quarantine/{chunk}/{approve\|reject\|revise}` | reviewer | transactional transition |
| GET/POST | `/api/conflicts`, `/api/conflicts/{id}/resolve` | reader / reviewer | claim conflicts |
| GET | `/api/ledger`, `/api/exposures`, `/api/audit`, `/api/stats` | reader / reviewer | forensics |
| POST/GET | `/api/snapshots`, `/api/snapshots/{id}/diff` | reviewer | time machine |
| GET/POST | `/api/scenarios`, `/api/scenarios/run` | — / reviewer | attack lab |
| POST | `/api/demo/unguarded-comparison` | admin + env flag | labelled measurement baseline |

Full schema: `docs/openapi.json`, or `/docs` while the API is running.

### Things the API will ignore on purpose

Send `{"query":"…","tenant_id":"victim","principal":"admin","trust_tier":"authoritative_signed"}`
and you get your own tenant's results plus:

```json
"ignored_privileged_fields": ["principal", "tenant_id", "trust_tier"],
"identity_source": "verified_token"
```

The fields are stripped before any handler can read them, and the attempt is audited. Set
`MF_STRICT_REJECT_FORGED_FIELDS=1` to get a 400 instead.

---

## 3. Framework adapters

No official plugin is claimed for any framework — none has been tested against pinned versions, and
claiming otherwise would be the kind of statement this project's contract forbids. These are
copy-and-paste adapters that work because a context pack is a plain dict.

### LangChain-style retriever

```python
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever


class MemoryFirewallRetriever(BaseRetriever):
    firewall: object
    tenant_id: str
    principal: str

    def _get_relevant_documents(self, query: str, **_: object) -> list[Document]:
        result = self.firewall.retrieve(
            query=query, tenant_id=self.tenant_id, principal=self.principal
        )
        return [
            Document(
                page_content=c.text,
                metadata={
                    "citation": c.citation,
                    "source_id": c.source_id,
                    "trust_tier": c.trust_tier,
                    "risk_tags": c.risk_tags,
                    "chunk_id": c.chunk_id,
                },
            )
            for c in result.context_chunks
        ]
```

### LlamaIndex-style

```python
from llama_index.core.schema import NodeWithScore, TextNode


def firewall_nodes(firewall, query, tenant_id, principal):
    result = firewall.retrieve(query=query, tenant_id=tenant_id, principal=principal)
    return [
        NodeWithScore(
            node=TextNode(
                text=c.text,
                id_=c.chunk_id,
                metadata={
                    "citation": c.citation,
                    "trust_tier": c.trust_tier,
                    "risk_tags": c.risk_tags,
                },
            ),
            score=-c.score,  # bm25 is lower-is-better
        )
        for c in result.context_chunks
    ]
```

In both cases: **carry `trust_tier` and `risk_tags` into your prompt.** Dropping them throws away the
only compensating control for the detector's ceiling.

---

## 4. Importing a local directory

```python
results = firewall.load_directory(
    "./knowledge-base", source="local-docs", tenant_id="acme", suffixes=(".md", ".txt")
)
```

Every file goes through the full pre-write pipeline. The importer resolves the root once and
requires every candidate to stay inside it, skips symlinked files *and* symlinked parents, enforces a
suffix allow-list and a size cap, and ignores `.git`, `node_modules`, `.venv`, `private`, `.ssh` and
friends. There is no URL-fetch path anywhere in the product, so there is no SSRF surface.

---

## 5. Optional model adapter

The default adapter performs **no network call** and declines rather than inventing an answer. The
whole test suite and `make eval` run against it, so nothing can silently acquire a dependency on a
paid provider.

```python
from memory_firewall.adapters.llm import LLMResponse


class MyAdapter:
    name = "my-provider"

    def complete(self, *, question: str, context_pack: dict) -> LLMResponse:
        if context_pack["insufficient_evidence"]:
            return LLMResponse(
                text=None, provider=self.name, declined=True, reason="no eligible evidence"
            )
        # The pack is already filtered. Pass the tags through to your system prompt.
        ...
```

An adapter only ever sees a pack the guard already produced — it cannot reach quarantined content.

---

## 6. Operational notes

| Variable | Default | |
|---|---|---|
| `MF_DB_PATH` | `data/memory-firewall.sqlite3` | manifests live beside it as `<path>.manifests` |
| `MF_MIN_RETRIEVAL_TRUST_TIER` | `external_untrusted` | raise to exclude weak sources entirely |
| `MF_STRICT_REJECT_FORGED_FIELDS` | `0` | `1` rejects instead of ignore-and-audit |
| `MF_READERS_MAY_QUERY_FUTURE_VALID_TIME` | `1` | `0` restricts future-dated reads to reviewers |
| `MF_HMAC_KEY` | unset | manifests become HMACs; keep the key outside both files |
| `MF_ENABLE_UNGUARDED_BASELINE` | `0` | demo/measurement only |
| `MF_DEV_EXPOSE_DEMO_TOKENS` | `0` | local demo only; loopback-only even when on |

**Back up both files.** `memory-firewall.sqlite3` and `memory-firewall.sqlite3.manifests` are a pair;
restoring one without the other makes every chunk fail its integrity recheck — which fails closed,
so you lose availability rather than safety, but you do lose it.

**Watch two metrics.** A rising `fail_closed` rate means the guard is refusing to prove eligibility;
a rising `integrity.alert` rate means stored content is changing underneath the application.
