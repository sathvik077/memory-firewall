"""Write-policy decision engine and the chunk state machine.

This is the only place that turns evidence into a state. Everything upstream (normalisation,
detection, claim extraction) produces facts; everything downstream (persistence, retrieval) obeys
the state. Keeping that boundary sharp is what lets ``docs/THREAT_MODEL.md`` publish a transition
table that a test can assert against (``tests/unit/test_policy_transitions.py``).

Decisions
---------
``ALLOW``             nothing of interest; chunk becomes ``active``.
``ALLOW_WITH_FLAGS``  retrievable, but carries visible findings. This is the deliberate answer to
                      Scenario F / MF-SEED-06: a security runbook that *quotes* an injection string
                      stays usable and is labelled, instead of being hard-blocked. The price of
                      that choice is measured as benign-flag rate by ``make eval``.
``REVIEW_REQUIRED``   withheld from active memory pending a human. Used for medium-severity signals
                      from weak sources, for anything suspicious from an *authority* (an authority
                      does not get a free pass, but neither is it silently quarantined), and for a
                      legitimate-looking claim disagreement.
``QUARANTINE``        withheld and queued as suspected poisoning.
``REJECT``            withheld and closed; only a reviewer can revise it into a new version.

Deterministic safety boundaries come first and are not negotiable by any score: a revoked source, a
tenant mismatch, a failed manifest or a quarantined state is always excluded at retrieval
regardless of what this engine decided at write time (``CLAUDE.md`` §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ._version import POLICY_REVISION
from .claims import ClaimConflict
from .config import TRUST_ORDER, FirewallConfig
from .detector import SEVERITY_ORDER, ScanReport

__all__ = [
    "DECISION_STATE",
    "TRANSITIONS",
    "Decision",
    "PolicyOutcome",
    "decide_write",
    "transition_table_markdown",
]

Decision = str

#: Decision → persisted state. Only ``active`` is retrievable.
DECISION_STATE: dict[str, str] = {
    "ALLOW": "active",
    "ALLOW_WITH_FLAGS": "active",
    "REVIEW_REQUIRED": "review_required",
    "QUARANTINE": "quarantined",
    "REJECT": "rejected",
}

#: Reviewer transitions. ``(current_state, decision) -> new_state``. Anything absent is refused by
#: ``review.py`` rather than defaulting to something permissive.
TRANSITIONS: dict[tuple[str, str], str] = {
    ("quarantined", "approve"): "active",
    ("quarantined", "reject"): "rejected",
    ("quarantined", "revise"): "superseded",
    ("review_required", "approve"): "active",
    ("review_required", "reject"): "rejected",
    ("review_required", "revise"): "superseded",
    ("active", "reject"): "rejected",
    ("active", "revise"): "superseded",
    ("rejected", "revise"): "superseded",
}


@dataclass(slots=True)
class PolicyOutcome:
    decision: str
    state: str
    reasons: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    max_severity: str = "none"
    unmitigated_max_severity: str = "none"
    policy_revision: str = POLICY_REVISION
    claim_conflicts: list[ClaimConflict] = field(default_factory=list)

    @property
    def retrievable(self) -> bool:
        return self.state == "active"

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "state": self.state,
            "reasons": list(self.reasons),
            "risk_score": self.risk_score,
            "max_severity": self.max_severity,
            "unmitigated_max_severity": self.unmitigated_max_severity,
            "policy_revision": self.policy_revision,
        }


def _rank(tier: str) -> int:
    return TRUST_ORDER.get(tier, 0)


def decide_write(
    scan_report: ScanReport,
    *,
    source_trust_tier: str,
    conflicts: list[ClaimConflict] | None = None,
    config: FirewallConfig | None = None,
) -> PolicyOutcome:
    """Decide the fate of one chunk.

    The severity that drives the decision is the **unmitigated** maximum: a finding downgraded by
    the quotation mitigator deliberately loses its power to block. Mitigated findings are still
    persisted and still shown, which is the difference between "flagged" and "blocked".
    """
    config = config or FirewallConfig()
    conflicts = conflicts or []
    tier_rank = _rank(source_trust_tier)
    unmit = scan_report.unmitigated_max_severity
    reasons: list[str] = []

    decision = "ALLOW"

    if unmit == "critical":
        if tier_rank >= TRUST_ORDER["authoritative_reviewed"]:
            decision = "REVIEW_REQUIRED"
            reasons.append(
                "critical signal in content from an authoritative source: held for review rather "
                "than quarantined, because an authority may legitimately publish an attack example"
            )
        else:
            decision = "QUARANTINE"
            reasons.append(
                f"critical signal from a {source_trust_tier} source: quarantined before entering "
                "active memory"
            )
    elif unmit == "high":
        if tier_rank <= TRUST_ORDER["unreviewed_internal"] and config.quarantine_untrusted_on_high:
            decision = "QUARANTINE"
            reasons.append(f"high-severity signal from a {source_trust_tier} source")
        else:
            decision = "REVIEW_REQUIRED"
            reasons.append(
                f"high-severity signal from a {source_trust_tier} source: reviewer decision required"
            )
    elif unmit == "medium":
        if tier_rank <= TRUST_ORDER["unreviewed_internal"]:
            decision = "REVIEW_REQUIRED"
            reasons.append(f"medium-severity signal from a {source_trust_tier} source")
        else:
            decision = "ALLOW_WITH_FLAGS"
            reasons.append("medium-severity signal from a trusted source: allowed and flagged")
    elif unmit in {"low", "info"}:
        decision = "ALLOW_WITH_FLAGS"
        reasons.append(f"{unmit}-severity signal recorded; content remains retrievable")
    elif scan_report.findings:
        decision = "ALLOW_WITH_FLAGS"
        reasons.append(
            "all findings were mitigated as quoted/example context (MF-M001); content remains "
            "retrievable and visibly flagged"
        )

    # --- claim-integrity escalation -----------------------------------------------------------
    # A weaker source changing a value a stronger authority already set is the core threat in this
    # product's governed domain, and it can carry no lexical signal at all ("Refunds are now 2
    # days."). It therefore escalates independently of the detector.
    unauthorized = [c for c in conflicts if c.unauthorized]
    legitimate = [c for c in conflicts if not c.unauthorized]

    if unauthorized:
        detail = unauthorized[0].detail
        if tier_rank <= TRUST_ORDER["unreviewed_internal"]:
            if _severity_rank(decision) < _severity_rank("QUARANTINE"):
                decision = "QUARANTINE"
            reasons.append(f"unauthorized change to a governed claim: {detail}")
        else:
            if _severity_rank(decision) < _severity_rank("REVIEW_REQUIRED"):
                decision = "REVIEW_REQUIRED"
            reasons.append(
                f"governed claim changed by a source of lower authority than the current value: {detail}"
            )
    elif legitimate and _severity_rank(decision) < _severity_rank("REVIEW_REQUIRED"):
        decision = "REVIEW_REQUIRED"
        reasons.append(
            "governed claim disagrees with an existing claim of equal or higher authority: "
            f"{legitimate[0].detail}. This is a review item, not a maliciousness finding."
        )

    if not reasons:
        reasons.append("no risk signal and no claim conflict")

    return PolicyOutcome(
        decision=decision,
        state=DECISION_STATE[decision],
        reasons=reasons,
        risk_score=scan_report.risk_score,
        max_severity=scan_report.max_severity,
        unmitigated_max_severity=unmit,
        claim_conflicts=conflicts,
    )


_DECISION_RANK = {
    "ALLOW": 0,
    "ALLOW_WITH_FLAGS": 1,
    "REVIEW_REQUIRED": 2,
    "QUARANTINE": 3,
    "REJECT": 4,
}


def _severity_rank(decision: str) -> int:
    return _DECISION_RANK.get(decision, 0)


def transition_table_markdown() -> str:
    """Render the write-decision and reviewer-transition tables (used by docs + a doc test)."""
    lines = [
        "| Unmitigated max severity | Source trust tier | Decision | Persisted state | Retrievable |",
        "|---|---|---|---|---|",
    ]
    tiers = sorted(TRUST_ORDER, key=lambda t: TRUST_ORDER[t])
    for severity in ("none", "info", "low", "medium", "high", "critical"):
        for tier in tiers:
            report = ScanReport()
            if severity != "none":
                from .detector import Finding  # local import keeps module import order simple

                report.findings.append(
                    Finding(
                        rule_id="SYNTHETIC",
                        rule_family="synthetic",
                        severity=severity,
                        confidence=1.0,
                        confidence_semantics="table generation only",
                        evidence_start=0,
                        evidence_end=1,
                        evidence_text="",
                    )
                )
            outcome = decide_write(report, source_trust_tier=tier)
            lines.append(
                f"| {severity} | `{tier}` | `{outcome.decision}` | `{outcome.state}` | "
                f"{'yes' if outcome.retrievable else 'no'} |"
            )
    lines.append("")
    lines.append("| Current state | Reviewer decision | New state |")
    lines.append("|---|---|---|")
    for (state, decision), new_state in sorted(TRANSITIONS.items()):
        lines.append(f"| `{state}` | `{decision}` | `{new_state}` |")
    lines.append("")
    lines.append(
        "Any (state, decision) pair absent from the second table is refused with HTTP 409 rather "
        "than defaulting to a permissive outcome."
    )
    assert SEVERITY_ORDER  # module coupling is intentional; keeps the table in step with severities
    return "\n".join(lines)
