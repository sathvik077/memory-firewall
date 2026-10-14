"""Memory Firewall — a provenance-aware trust boundary for agent memory and RAG.

Public surface::

    from memory_firewall import MemoryFirewall, MemoryFirewallEngine, FirewallConfig

See ``README.md`` for the 30-second quickstart and ``docs/SECURITY.md`` for the bounded security
claims. The short version of those bounds: this protects content that actually flows through its
pipeline, it detects a closed set of signals rather than all semantic poisoning, and a digest proves
consistency rather than safety.
"""

from __future__ import annotations

from ._version import DETECTOR_VERSION, POLICY_REVISION, SCHEMA_VERSION, __version__
from .config import TRUST_ORDER, FirewallConfig
from .contextpack import ContextPack
from .detector import Finding, ScanReport, scan
from .engine import IngestResult, MemoryFirewallEngine, ReviewOutcome
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    FirewallError,
    NotFoundError,
    PolicyError,
    ValidationError,
)
from .identity import Principal
from .normalize import normalize_text
from .policy import decide_write
from .retrieval import RetrievalResult, RetrievedChunk
from .sdk import MemoryFirewall

__all__ = [
    "DETECTOR_VERSION",
    "POLICY_REVISION",
    "SCHEMA_VERSION",
    "TRUST_ORDER",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "ContextPack",
    "Finding",
    "FirewallConfig",
    "FirewallError",
    "IngestResult",
    "MemoryFirewall",
    "MemoryFirewallEngine",
    "NotFoundError",
    "PolicyError",
    "Principal",
    "RetrievalResult",
    "RetrievedChunk",
    "ReviewOutcome",
    "ScanReport",
    "ValidationError",
    "__version__",
    "decide_write",
    "normalize_text",
    "scan",
]
