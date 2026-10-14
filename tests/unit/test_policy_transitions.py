"""The write-decision matrix and the reviewer transition table.

These assertions are the executable form of the tables published in ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import pytest

from memory_firewall.claims import ClaimConflict, extract_claims
from memory_firewall.detector import Finding, ScanReport
from memory_firewall.policy import (
    DECISION_STATE,
    TRANSITIONS,
    decide_write,
    transition_table_markdown,
)


def report_with(severity: str, *, mitigated: bool = False) -> ScanReport:
    report = ScanReport()
    if severity != "none":
        report.findings.append(
            Finding(
                rule_id="TEST",
                rule_family="test",
                severity=severity,
                confidence=0.9,
                confidence_semantics="test",
                evidence_start=0,
                evidence_end=4,
                evidence_text="test",
                mitigated_by="MF-M001:quotation_marks" if mitigated else None,
            )
        )
    return report


@pytest.mark.parametrize(
    "severity,tier,expected",
    [
        ("none", "external_untrusted", "ALLOW"),
        ("none", "authoritative_reviewed", "ALLOW"),
        ("info", "external_untrusted", "ALLOW_WITH_FLAGS"),
        ("low", "external_untrusted", "ALLOW_WITH_FLAGS"),
        ("medium", "external_untrusted", "REVIEW_REQUIRED"),
        ("medium", "unreviewed_internal", "REVIEW_REQUIRED"),
        ("medium", "reviewed_internal", "ALLOW_WITH_FLAGS"),
        ("medium", "authoritative_reviewed", "ALLOW_WITH_FLAGS"),
        ("high", "external_untrusted", "QUARANTINE"),
        ("high", "unreviewed_internal", "QUARANTINE"),
        ("high", "reviewed_internal", "REVIEW_REQUIRED"),
        ("high", "authoritative_signed", "REVIEW_REQUIRED"),
        ("critical", "external_untrusted", "QUARANTINE"),
        ("critical", "reviewed_internal", "QUARANTINE"),
        ("critical", "authoritative_reviewed", "REVIEW_REQUIRED"),
        ("critical", "authoritative_signed", "REVIEW_REQUIRED"),
    ],
)
def test_write_decision_matrix(severity: str, tier: str, expected: str) -> None:
    outcome = decide_write(report_with(severity), source_trust_tier=tier)
    assert outcome.decision == expected
    assert outcome.state == DECISION_STATE[expected]


def test_mitigated_findings_lose_their_power_to_block() -> None:
    outcome = decide_write(
        report_with("critical", mitigated=True), source_trust_tier="external_untrusted"
    )
    assert outcome.decision == "ALLOW_WITH_FLAGS"
    assert outcome.state == "active"
    assert "mitigated" in " ".join(outcome.reasons)


def test_only_active_state_is_retrievable() -> None:
    for decision, state in DECISION_STATE.items():
        outcome = decide_write(report_with("none"), source_trust_tier="reviewed_internal")
        del outcome
        assert (state == "active") == (decision in {"ALLOW", "ALLOW_WITH_FLAGS"})


def _conflict(unauthorized: bool) -> ClaimConflict:
    authoritative = extract_claims(
        "Refunds are allowed within 30 days.", authority_tier="authoritative_reviewed"
    )[0]
    incoming = extract_claims(
        "Refunds are now 2 days.",
        authority_tier="external_untrusted" if unauthorized else "authoritative_reviewed",
    )[0]
    from memory_firewall.claims import compare_claims

    conflict = compare_claims(incoming, authoritative)
    assert conflict is not None
    assert conflict.unauthorized is unauthorized
    return conflict


def test_unauthorized_claim_mutation_escalates_with_no_lexical_signal() -> None:
    """'Refunds are now 2 days.' trips no detector rule; the claim graph must still catch it."""
    outcome = decide_write(
        report_with("none"),
        source_trust_tier="external_untrusted",
        conflicts=[_conflict(unauthorized=True)],
    )
    assert outcome.decision == "QUARANTINE"
    assert "unauthorized change to a governed claim" in " ".join(outcome.reasons)


def test_legitimate_disagreement_is_review_not_quarantine() -> None:
    outcome = decide_write(
        report_with("none"),
        source_trust_tier="authoritative_reviewed",
        conflicts=[_conflict(unauthorized=False)],
    )
    assert outcome.decision == "REVIEW_REQUIRED"
    assert "not a maliciousness finding" in " ".join(outcome.reasons)


def test_claim_escalation_never_downgrades_a_worse_decision() -> None:
    outcome = decide_write(
        report_with("critical"),
        source_trust_tier="external_untrusted",
        conflicts=[_conflict(unauthorized=False)],
    )
    assert outcome.decision == "QUARANTINE"


def test_reviewer_transition_table_is_closed() -> None:
    """Any pair absent from the table must stay absent — absence means 'refuse', not 'allow'."""
    assert TRANSITIONS[("quarantined", "approve")] == "active"
    assert TRANSITIONS[("quarantined", "reject")] == "rejected"
    assert TRANSITIONS[("review_required", "approve")] == "active"
    assert ("rejected", "approve") not in TRANSITIONS
    assert ("superseded", "approve") not in TRANSITIONS
    assert ("revoked", "approve") not in TRANSITIONS
    for (state, decision), new_state in TRANSITIONS.items():
        assert decision in {"approve", "reject", "revise"}
        assert new_state in {"active", "rejected", "superseded"}
        assert state != new_state or state == "active"


def test_every_reason_is_human_readable() -> None:
    outcome = decide_write(report_with("high"), source_trust_tier="external_untrusted")
    assert outcome.reasons
    assert all(len(r) > 20 for r in outcome.reasons)


def test_transition_table_markdown_renders_both_tables() -> None:
    md = transition_table_markdown()
    assert "Unmitigated max severity" in md
    assert "Reviewer decision" in md
    assert "`QUARANTINE`" in md
    assert "refused with HTTP 409" in md
