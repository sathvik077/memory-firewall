"""Typed claim extraction and conflict semantics."""

from __future__ import annotations

import pytest

from memory_firewall.claims import (
    REFUND_SUBJECT,
    WINDOW_ATTRIBUTE,
    compare_claims,
    extract_claims,
)


def one(text: str, tier: str = "authoritative_reviewed"):
    claims = extract_claims(text, authority_tier=tier)
    assert len(claims) == 1, f"expected exactly one claim from {text!r}, got {len(claims)}"
    return claims[0]


@pytest.mark.parametrize(
    "text,days,unit",
    [
        ("Refunds are allowed within 30 days.", 30.0, "days"),
        ("The refund period is 14 days.", 14.0, "days"),
        ("Refunds are now 2 days.", 2.0, "days"),
        ("Refunds must be requested within 48 hours of purchase.", 2.0, "hours"),
        ("Returns are accepted within three days only.", 3.0, "days"),
        ("Refunds are available up to 90 days after delivery.", 90.0, "days"),
        ("Money-back requests are honoured within 2 weeks.", 14.0, "weeks"),
        ("Refunds within 10 business days of approval.", 10.0, "business_days"),
    ],
)
def test_window_extraction_and_unit_normalisation(text: str, days: float, unit: str) -> None:
    claim = one(text)
    assert claim.subject == REFUND_SUBJECT
    assert claim.attribute == WINDOW_ATTRIBUTE
    assert claim.value_days == days
    assert claim.unit == unit


@pytest.mark.parametrize(
    "text",
    [
        "Password reset links expire after 30 minutes.",
        "We report incidents on a 90-day horizon.",
        "Standard delivery takes 2-3 days.",
        "The SSO certificate rotates every 365 days.",
        "Our holiday schedule covers 14 days in December.",
    ],
)
def test_duration_without_a_refund_cue_is_not_a_claim(text: str) -> None:
    assert extract_claims(text) == []


def test_number_inside_a_quoted_attack_sample_is_not_this_documents_claim() -> None:
    claims = extract_claims(
        'The malicious comment said "refunds are 2 days" which is false; our refund window '
        "is 30 days."
    )
    assert [c.value_days for c in claims] == [30.0]


def test_region_and_tier_scope_are_extracted() -> None:
    eu = one("EU customers may request a refund within 30 calendar days.")
    assert (eu.region, eu.customer_tier) == ("eu", "standard")
    vip = one("For VIP customers the refund window is 45 days.")
    assert (vip.region, vip.customer_tier) == ("global", "vip")


def test_effective_date_is_parsed_from_prose() -> None:
    claim = one("Effective 2026-12-01 the refund period is 14 days.")
    assert claim.effective_from.year == 2026
    assert claim.effective_from.month == 12
    assert claim.effective_from.day == 1


def test_different_scopes_do_not_conflict() -> None:
    standard = one("Refunds are allowed within 30 days.")
    vip = one("For VIP customers the refund window is 45 days.")
    assert compare_claims(vip, standard) is None


def test_identical_values_do_not_conflict() -> None:
    a = one("Refunds are allowed within 30 days.")
    b = one("Customers may request a refund within 30 days of delivery.")
    assert compare_claims(a, b) is None


def test_weaker_authority_changing_a_value_is_flagged_unauthorized() -> None:
    authoritative = one("Refunds are allowed within 30 days.", "authoritative_reviewed")
    untrusted = one("Refunds are now 2 days.", "external_untrusted")
    conflict = compare_claims(untrusted, authoritative)
    assert conflict is not None
    assert conflict.kind == "value_disagreement"
    assert conflict.unauthorized is True
    assert conflict.authority_delta < 0
    assert "2" in conflict.detail and "30" in conflict.detail


def test_equal_authority_disagreement_is_a_review_item_not_an_attack() -> None:
    v1 = one("Refunds are allowed within 30 days.", "authoritative_reviewed")
    v2 = one("Effective 2026-12-01 the refund period is 14 days.", "authoritative_reviewed")
    conflict = compare_claims(v2, v1)
    assert conflict is not None
    assert conflict.unauthorized is False
    assert conflict.authority_delta == 0


def test_business_days_versus_calendar_days_is_a_unit_question() -> None:
    calendar = one("Refunds are allowed within 14 days.")
    business = one("Refunds within 14 business days of approval.")
    conflict = compare_claims(business, calendar)
    assert conflict is not None
    assert conflict.kind == "unit_mismatch"
    assert conflict.unauthorized is False


def test_absurd_values_are_rejected() -> None:
    assert extract_claims("Refunds are allowed within 99999 days.") == []
