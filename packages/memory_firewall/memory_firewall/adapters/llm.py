"""Optional LLM adapter interface.

Required by ``CLAUDE.md`` §3 to exist, and required *not* to be required: the default demo, the
whole test suite and ``make eval`` run with :class:`NullLLMAdapter`, so nothing can silently depend
on a paid provider or a network call. An adapter receives a already-filtered context pack — it never
sees quarantined or excluded text — and must report which provider it used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = ["LLMAdapter", "LLMResponse", "NullLLMAdapter", "get_adapter"]


@dataclass(slots=True)
class LLMResponse:
    text: str | None
    provider: str
    used_model: str | None = None
    tokens: int | None = None
    declined: bool = False
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "provider": self.provider,
            "used_model": self.used_model,
            "tokens": self.tokens,
            "declined": self.declined,
            "reason": self.reason,
        }


class LLMAdapter(Protocol):
    """Anything that can turn an already-guarded context pack into prose."""

    name: str

    def complete(self, *, question: str, context_pack: dict[str, Any]) -> LLMResponse: ...


class NullLLMAdapter:
    """The default. Never calls out; declines when there is no eligible evidence."""

    name = "null"

    def complete(self, *, question: str, context_pack: dict[str, Any]) -> LLMResponse:
        if context_pack.get("insufficient_evidence", True):
            return LLMResponse(
                text=None,
                provider=self.name,
                declined=True,
                reason=(
                    "No eligible evidence passed the retrieval guard, so no answer is produced. "
                    "This is the intended fail-safe behaviour."
                ),
            )
        citations = ", ".join(context_pack.get("citations", []))
        deterministic = context_pack.get("answer")
        if deterministic:
            return LLMResponse(text=f"{deterministic} [{citations}]", provider=self.name)
        return LLMResponse(
            text=None,
            provider=self.name,
            declined=True,
            reason=(
                "Eligible evidence was retrieved but it contains no claim of the governed typed "
                "domain, and no language model is configured. Configure an adapter to summarise "
                f"free text. Evidence: [{citations}]"
            ),
        )


def get_adapter(name: str | None = None) -> LLMAdapter:
    """Resolve an adapter by name. Unknown names fall back to the null adapter, never to a network
    call, and the choice is visible in every response via ``provider``."""
    chosen = (name or os.environ.get("MF_LLM_ADAPTER") or "null").strip().lower()
    if chosen in {"", "null", "none", "offline"}:
        return NullLLMAdapter()
    # Deliberately no built-in provider client. Register your own adapter object instead; this keeps
    # the default install free of API clients and keeps `make verify` offline.
    return NullLLMAdapter()
