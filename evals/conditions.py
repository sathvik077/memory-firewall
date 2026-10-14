"""The four measured conditions (MF-19).

All four run over an **identical corpus, in identical order, with identical splits** so the
denominators are comparable. The only thing that varies is which gate is switched on:

=====================  ==========================  ==========================================
condition              write screening             retrieval
=====================  ==========================  ==========================================
``unguarded``          none                        blind lexical search over everything
``keyword_only``       a naive phrase blocklist    blind lexical search over what passed
``write_only``         full Memory Firewall policy blind lexical search over what passed
``full``               full Memory Firewall policy the permission-aware guarded query
=====================  ==========================  ==========================================

Two properties of this design matter for honesty:

* ``write_only`` is not a strawman. It is the *real* Memory Firewall write policy — the same
  detector, the same claim graph, the same decisions. The only thing it lacks is the second gate.
  So any difference between ``write_only`` and ``full`` is attributable to the pre-retrieval guard
  alone, which is the question RQ1 asks.
* Every condition's retrieval is measured on the same index contents it would actually have,
  **plus** the same set of stale-index poison rows. A write-time gate cannot retroactively clean an
  index it never saw, and pretending otherwise would flatter ``write_only``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["CONDITIONS", "Condition", "keyword_screen"]

#: A naive keyword screen, representing "keyword-only text screening" from CLAUDE.md §7 Stage 5.
#: Intentionally the kind of list a team writes in an afternoon: literal, case-insensitive phrases
#: with no normalisation, no context awareness and no claim model.
KEYWORD_BLOCKLIST: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "system override",
    "system:",
    "do not cite",
    "approved_by",
    "trust_tier",
    "<script",
    "javascript:",
    "[inst]",
    "begin system prompt",
    "you are now",
    "forget everything",
    "exfiltrate",
)

_BLOCK_RE = re.compile("|".join(re.escape(p) for p in KEYWORD_BLOCKLIST), re.IGNORECASE)


def keyword_screen(text: str) -> tuple[bool, list[str]]:
    """Return ``(blocked, matched_phrases)`` for the naive baseline.

    Deliberately operates on the **raw** text with no Unicode normalisation, which is why
    zero-width and homoglyph evasions walk straight past it — that difference is one of the
    things the evaluation is measuring.
    """
    matches = sorted({m.group(0).lower() for m in _BLOCK_RE.finditer(text)})
    return (bool(matches), matches)


@dataclass(frozen=True, slots=True)
class Condition:
    key: str
    label: str
    write_screening: str
    retrieval: str
    description: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "write_screening": self.write_screening,
            "retrieval": self.retrieval,
            "description": self.description,
        }


CONDITIONS: tuple[Condition, ...] = (
    Condition(
        "unguarded",
        "Naive unguarded RAG",
        "none",
        "blind lexical search",
        "Everything ingested is indexed and retrievable. The control: what a normal RAG pipeline "
        "would have exposed on this corpus.",
    ),
    Condition(
        "keyword_only",
        "Keyword-only screening",
        "naive phrase blocklist on raw text",
        "blind lexical search",
        "A literal phrase blocklist at ingestion, no normalisation and no retrieval gate — the "
        "common first attempt at this problem.",
    ),
    Condition(
        "write_only",
        "Write-time firewall only",
        "full Memory Firewall write policy",
        "blind lexical search",
        "The real detector, claim graph and write policy, but retrieval performs no tenant, ACL, "
        "state, temporal or integrity check.",
    ),
    Condition(
        "full",
        "Write + retrieve guard (Memory Firewall)",
        "full Memory Firewall write policy",
        "permission-aware guarded query + integrity recheck",
        "Both enforcement points. The product.",
    ),
)
