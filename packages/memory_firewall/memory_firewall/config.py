"""Runtime configuration.

All security-relevant switches default to the *safe* value. The demo profile may relax presentation
concerns (e.g. exposing the labelled unguarded-baseline endpoint) but never the guard itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["TRUST_ORDER", "FirewallConfig", "TrustTier", "from_env"]

TrustTier = str

#: Ordered weakest → strongest. Used for retrieval trust policy and claim authority comparison.
TRUST_ORDER: dict[str, int] = {
    "external_untrusted": 0,
    "unreviewed_internal": 1,
    "reviewed_internal": 2,
    "authoritative_reviewed": 3,
    "authoritative_signed": 4,
}

DEFAULT_DB_PATH = "data/memory-firewall.sqlite3"


@dataclass(slots=True)
class FirewallConfig:
    """Engine configuration.

    Attributes
    ----------
    min_retrieval_trust_tier:
        Chunks from a source weaker than this tier are excluded at retrieval even when ``active``.
        Default ``external_untrusted`` (i.e. tier alone excludes nothing) because exclusion is the
        detector's and the reviewer's job; raising it is a documented deployment hardening knob and
        is one of the four measured eval conditions.
    quarantine_untrusted_on_high:
        Quarantine (rather than hold for review) when a HIGH finding comes from a source at or
        below ``unreviewed_internal``.
    max_document_bytes / max_chunk_chars:
        Hard input bounds (MF-23).
    hmac_key:
        Optional key for tamper-evident manifests. Read from ``MF_HMAC_KEY``; never persisted in the
        content DB.
    enable_unguarded_baseline:
        Exposes ``POST /api/demo/unguarded-comparison`` (admin only, response labelled as a
        synthetic baseline). Off unless ``MF_ENABLE_UNGUARDED_BASELINE=1``.
    """

    db_path: Path = field(default_factory=lambda: Path(DEFAULT_DB_PATH))
    min_retrieval_trust_tier: str = "external_untrusted"
    quarantine_untrusted_on_high: bool = True
    max_document_bytes: int = 256 * 1024
    max_chunk_chars: int = 900
    chunk_overlap_chars: int = 0
    max_retrieve_limit: int = 25
    hmac_key: bytes | None = None
    enable_unguarded_baseline: bool = False
    strict_reject_forged_fields: bool = False
    #: Whether a non-reviewer may set `as_of_valid` to a future instant and so read a scheduled,
    #: not-yet-effective revision. Default True because "what will the policy be in December?" is a
    #: first-class feature and the release contract's seed vector MF-SEED-05 requires a reader to be
    #: able to ask it. Set False in a deployment that schedules confidential policy ahead of
    #: publication. Either way, valid time is NOT an access control — see docs/SECURITY.md.
    readers_may_query_future_valid_time: bool = True
    allowed_upload_suffixes: tuple[str, ...] = (".txt", ".md", ".json")

    def __post_init__(self) -> None:
        if self.min_retrieval_trust_tier not in TRUST_ORDER:
            raise ValueError(f"unknown trust tier: {self.min_retrieval_trust_tier}")
        self.db_path = Path(self.db_path)


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def from_env() -> FirewallConfig:
    key = os.environ.get("MF_HMAC_KEY") or None
    return FirewallConfig(
        db_path=Path(os.environ.get("MF_DB_PATH", DEFAULT_DB_PATH)),
        min_retrieval_trust_tier=os.environ.get(
            "MF_MIN_RETRIEVAL_TRUST_TIER", "external_untrusted"
        ),
        max_document_bytes=int(os.environ.get("MF_MAX_DOCUMENT_BYTES", 256 * 1024)),
        hmac_key=key.encode("utf-8") if key else None,
        enable_unguarded_baseline=_flag("MF_ENABLE_UNGUARDED_BASELINE"),
        strict_reject_forged_fields=_flag("MF_STRICT_REJECT_FORGED_FIELDS"),
        readers_may_query_future_valid_time=_flag(
            "MF_READERS_MAY_QUERY_FUTURE_VALID_TIME", default=True
        ),
    )
