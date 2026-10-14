"""Request and response models.

Every request model forbids unknown fields (``extra="forbid"``) so that a typo or an attempted
privilege field is a visible 422 rather than silent acceptance. Identity and privilege fields are
already stripped upstream in :func:`app.deps.clean_json_body`, so they never reach these models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TRUST_TIERS = Literal[
    "authoritative_signed",
    "authoritative_reviewed",
    "reviewed_internal",
    "unreviewed_internal",
    "external_untrusted",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CreateSourceRequest(StrictModel):
    source_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._\-]+$")
    #: Administrative state. Accepted here only because this route requires an admin bearer token.
    trust_tier_assignment: TRUST_TIERS = Field(
        description=(
            "The trust tier to assign. Named 'trust_tier_assignment' rather than 'trust_tier' "
            "because any field literally named 'trust_tier' is stripped from every request body as "
            "a forgeable field; this route's value is accepted only from an admin token."
        )
    )
    read_acl: list[str] = Field(default_factory=list, max_length=200)
    connector_type: str = Field(default="manual", max_length=60)
    owner: str | None = Field(default=None, max_length=120)
    expires_at: datetime | None = None


class SetAclRequest(StrictModel):
    read_acl: list[str] = Field(default_factory=list, max_length=200)


class RevokeSourceRequest(StrictModel):
    reason: str = Field(default="", max_length=500)


class IngestRequest(StrictModel):
    source_id: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=1_000_000)
    title: str | None = Field(default=None, max_length=300)
    uri: str | None = Field(default=None, max_length=1000)
    effective_from: datetime | None = None


class RevisionRequest(StrictModel):
    source_id: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=1_000_000)
    title: str | None = Field(default=None, max_length=300)
    effective_from: datetime | None = None


class RetrieveRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=25)
    as_of_valid: datetime | None = Field(
        default=None, description="Valid-time coordinate: what was in force at this instant."
    )
    as_of_recorded: datetime | None = Field(
        default=None,
        description="System-time coordinate: what the system believed at this instant.",
    )
    include_trace: bool = Field(
        default=False,
        description="Admin only. Ignored for readers and reviewers, who never receive a trace.",
    )


class ContextPackRequest(RetrieveRequest):
    include_answer: bool = True


class QaRequest(StrictModel):
    question: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=25)
    as_of_valid: datetime | None = None


class ReviewRequest(StrictModel):
    decision: Literal["approve", "reject", "revise"]
    reason: str = Field(min_length=1, max_length=1000)
    target_type: Literal["chunk", "version"] = "chunk"
    effective_from: datetime | None = None
    revised_text: str | None = Field(default=None, max_length=1_000_000)


class ResolveConflictRequest(StrictModel):
    resolution: Literal["resolved_supersede", "resolved_dismissed", "resolved_rejected"]
    reason: str = Field(min_length=1, max_length=1000)


class SnapshotRequest(StrictModel):
    label: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=1000)
    as_of_valid: datetime | None = None
    as_of_recorded: datetime | None = None


class ReplayRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=25)


class UnguardedComparisonRequest(StrictModel):
    query: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=25)


class ScenarioRunRequest(StrictModel):
    scenario_id: str = Field(min_length=1, max_length=60)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    schema_version: str | None
    detector_version: str
    policy_revision: str
    fts5: bool
    database: str
    guard_enforced: bool = True
    unguarded_baseline_enabled: bool = False
    notes: list[str] = Field(default_factory=list)


class Envelope(BaseModel):
    """Common response wrapper so that provenance of the *answer itself* is always visible."""

    identity_source: Literal["verified_token"] = "verified_token"
    ignored_privileged_fields: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
