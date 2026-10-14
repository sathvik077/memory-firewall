"""Ingestion and model adapters.

``directory`` is a real, safety-checked local importer. ``llm`` is an interface with a null default
so that nothing in the required demo, tests or evals can call out to a paid provider.
"""

from __future__ import annotations

from .directory import DirectoryAdapter, DirectoryDocument
from .llm import LLMAdapter, NullLLMAdapter, get_adapter

__all__ = [
    "DirectoryAdapter",
    "DirectoryDocument",
    "LLMAdapter",
    "NullLLMAdapter",
    "get_adapter",
]
