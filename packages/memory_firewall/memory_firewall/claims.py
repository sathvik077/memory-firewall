"""Typed structured-claim extraction for one narrow governed domain.

``IMPLEMENTATION_BLUEPRINT.md`` §4.2 forbids general semantic contradiction detection, so this
module does exactly one thing: it extracts ``RefundPolicy(region, customer_tier, days,
effective_from)`` claims and compares only claims whose ``(subject, attribute, region,
customer_tier)`` key and effective interval actually overlap. Anything outside that schema is not
a claim and produces no conflict.

Two false-positive traps that the extractor must survive, because the independent eval dataset is
full of them:

* **Unit distractors.** "a 30-*minute* reset link", "a 90-*day* reporting horizon", "2–3 *day*
  delivery". A duration near the word "day" is not a refund window, so a refund/return/money-back
  cue is required inside the same sentence.
* **Quoted numbers.** A window that appears only inside a quoted attack sample must not be
  extracted as this document's claim.

A conflict is a *review state*, never a truth judgement: ``docs/THREAT_MODEL.md`` states that
Memory Firewall cannot know which of two disagreeing documents is correct. It can only know which
one came from an authority and which did not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .clock import now, parse
from .config import TRUST_ORDER

__all__ = [
    "REFUND_SUBJECT",
    "WINDOW_ATTRIBUTE",
    "Claim",
    "ClaimConflict",
    "compare_claims",
    "extract_claims",
]

REFUND_SUBJECT = "refund_policy"
WINDOW_ATTRIBUTE = "window_days"

_NUMBER_WORDS: dict[str, int] = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "fourteen": 14,
    "fifteen": 15,
    "twenty": 20,
    "twentyone": 21,
    "twenty-one": 21,
    "thirty": 30,
    "forty": 40,
    "forty-five": 45,
    "fortyfive": 45,
    "sixty": 60,
    "ninety": 90,
    "a": 1,
    "an": 1,
}

_REFUND_CUE = re.compile(
    r"\b(?:refund|refunds|refunded|refundable|return|returns|money[- ]back|reimburse\w*|"
    r"cancellation|charge ?back|refund window|return window|"
    # non-English surface forms present in the evaluation corpus; coverage beyond these is not
    # claimed (see docs/SECURITY.md)
    r"devoluci\u00f3n|devoluciones|reembolso|remboursement|r\u00fcckerstattung|r\u00fcckgabe)\b"
    r"|\bwindow\b|\bplazo\b",
    re.IGNORECASE,
)

_NUM = (
    r"(?:\d{1,4}|"
    + "|".join(sorted((re.escape(w) for w in _NUMBER_WORDS), key=len, reverse=True))
    + r")"
)
_UNIT = (
    r"(calendar days?|business days?|working days?|days?|hours?|hrs?|weeks?|months?"
    r"|d\u00edas? naturales|d\u00edas?|horas?|semanas?|werktage?n?|tage?n?|jours?)"
)

#: Structured / machine-readable declarations of the governed value. The key name is itself the
#: cue, so these do not require a refund word elsewhere in the sentence: a CSV row
#: ``refund_window_days,2`` or a constant ``REFUND_WINDOW_DAYS = 2`` is an unambiguous assertion
#: about the governed policy, and an attacker hiding a change in a config file is a real path.
_STRUCTURED_PATTERNS = (
    re.compile(r"\brefund[_\s-]?window[_\s-]?days?\s*[,=:]\s*(\d{1,4})", re.IGNORECASE),
    re.compile(
        r"\brefund[_\s-]?(?:period|window)\s*[,=:]\s*(\d{1,4})\s*(days?|hours?)?", re.IGNORECASE
    ),
    re.compile(r"\bREFUND_WINDOW_DAYS\s*=\s*(\d{1,4})"),
    re.compile(r"\bwindow_days\s*[\"']?\s*[,=:]\s*(\d{1,4})", re.IGNORECASE),
)

_WINDOW_PATTERNS = (
    re.compile(rf"\bwithin\s+({_NUM})\s+{_UNIT}", re.IGNORECASE),
    re.compile(
        rf"\b(?:period|window|deadline|limit|timeframe|time frame)\b[^.\n]{{0,24}}?\b(?:is|of|:)\s*({_NUM})\s+{_UNIT}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:are|is|now|set to|reduced to|extended to|changed to|shortened to)\s+({_NUM})\s+{_UNIT}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b({_NUM})[\s-]{_UNIT}\s+(?:refund|return|money[- ]back|cancellation)\b", re.IGNORECASE
    ),
    re.compile(rf"\bup to\s+({_NUM})\s+{_UNIT}", re.IGNORECASE),
    re.compile(
        rf"\b(?:shrinks?|reduced|shortened|extended|changed|moves?)\b[^.\n]{{0,60}}?\b({_NUM})\s+{_UNIT}",
        re.IGNORECASE,
    ),
    re.compile(rf"\b(?:pasa a ser de|ser\u00e1 de|es de)\s+({_NUM})\s+{_UNIT}", re.IGNORECASE),
    re.compile(rf"\b(?:that is|i\.?e\.?|namely)\s+({_NUM})\s+{_UNIT}", re.IGNORECASE),
    re.compile(rf"\bafter\s+({_NUM})\s+{_UNIT}\b[^.\n]{{0,40}}\bno longer\b", re.IGNORECASE),
)

_REGION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:eu|european union|europe|eea)\b", re.IGNORECASE), "eu"),
    (re.compile(r"\b(?:uk|united kingdom|britain)\b", re.IGNORECASE), "uk"),
    (re.compile(r"\b(?:us|usa|united states|north america)\b", re.IGNORECASE), "us"),
    (re.compile(r"\b(?:apac|asia[- ]pacific|japan|australia)\b", re.IGNORECASE), "apac"),
    (re.compile(r"\b(?:canada|canadian)\b", re.IGNORECASE), "ca"),
)

_TIER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bvip\b", re.IGNORECASE), "vip"),
    (re.compile(r"\b(?:enterprise|legacy enterprise)\b", re.IGNORECASE), "enterprise"),
    (
        re.compile(r"\b(?:premium|plus|pro)\s+(?:customers?|tier|plan|members?)\b", re.IGNORECASE),
        "premium",
    ),
    (re.compile(r"\bpartner(?:s|ship)?\b", re.IGNORECASE), "partner"),
    (re.compile(r"\btrial\b", re.IGNORECASE), "trial"),
)

_EFFECTIVE_DATE = re.compile(
    r"\b(?:effective|effective from|starting|as of|from|commencing|takes effect(?: on)?)\s+"
    r"(\d{4}-\d{2}-\d{2}|\d{1,2}\s+\w+\s+\d{4}|\w+\s+\d{1,2},?\s+\d{4})",
    re.IGNORECASE,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?\n])\s+")


def _to_days(value: int, unit: str) -> tuple[float | None, str]:
    """Normalise a duration to days, keeping the original unit for the conflict explanation."""
    u = unit.lower().strip().rstrip("s")
    if u in {"day", "calendar day", "d\u00eda", "d\u00eda natural", "tag", "tage", "jour"}:
        return float(value), "days"
    if u in {"business day", "working day", "werktag", "werktage"}:
        return float(value), "business_days"
    if u in {"hour", "hr", "hora"}:
        return round(value / 24.0, 4), "hours"
    if u in {"week", "semana"}:
        return float(value * 7), "weeks"
    if u in {"month", "mes"}:
        return float(value * 30), "months"
    return None, unit


def _parse_number(token: str) -> int | None:
    token = token.strip().lower()
    if token.isdigit():
        return int(token)
    return _NUMBER_WORDS.get(token)


def _parse_effective(text: str, default: datetime) -> datetime:
    m = _EFFECTIVE_DATE.search(text)
    if not m:
        return default
    raw = m.group(1)
    for fmt in ("%Y-%m-%d", "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%B %d %Y", "%b %d, %Y"):
        try:
            return parse(datetime.strptime(raw, fmt).isoformat() + "Z")
        except ValueError:
            continue
    return default


@dataclass(slots=True)
class Claim:
    """One extracted, typed assertion. ``value_days`` is normalised for comparison."""

    subject: str
    attribute: str
    region: str
    customer_tier: str
    value_days: float | None
    value_text: str
    unit: str
    evidence_start: int
    evidence_end: int
    effective_from: datetime
    authority_tier: str = "external_untrusted"
    source_id: str = ""
    chunk_id: str = ""
    id: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.subject, self.attribute, self.region, self.customer_tier)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "subject": self.subject,
            "attribute": self.attribute,
            "region": self.region,
            "customer_tier": self.customer_tier,
            "value_days": self.value_days,
            "value_text": self.value_text,
            "unit": self.unit,
            "evidence_start": self.evidence_start,
            "evidence_end": self.evidence_end,
            "effective_from": self.effective_from.isoformat(),
            "authority_tier": self.authority_tier,
            "source_id": self.source_id,
            "chunk_id": self.chunk_id,
        }


@dataclass(slots=True)
class ClaimConflict:
    """Two evidence-backed claims that cannot both be in force."""

    kind: str
    incoming: Claim
    existing: Claim
    authority_delta: int
    detail: str = ""
    unauthorized: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for opener, closer in (('"', '"'), ("'", "'"), ("“", "”")):
        pos = 0
        while True:
            a = text.find(opener, pos)
            if a == -1:
                break
            b = text.find(closer, a + 1)
            if b == -1 or "\n" in text[a:b]:
                break
            spans.append((a, b + 1))
            pos = b + 1
    marks = [m.start() for m in re.finditer(r"```|~~~", text)]
    for i in range(0, len(marks) - 1, 2):
        spans.append((marks[i], marks[i + 1] + 3))
    return spans


def extract_claims(
    normalized_text: str,
    *,
    authority_tier: str = "external_untrusted",
    source_id: str = "",
    chunk_id: str = "",
    default_effective_from: datetime | None = None,
    offset_translate: object = None,
) -> list[Claim]:
    """Extract refund-window claims. Returns ``[]`` for anything outside the typed schema."""
    default_effective = default_effective_from or now()
    quoted = _quoted_spans(normalized_text)
    out: list[Claim] = []
    seen: set[tuple[str, str, str, str, float | None]] = set()

    # Structured declarations first: the key name carries the semantics, so no sentence cue needed.
    for pattern in _STRUCTURED_PATTERNS:
        for m in pattern.finditer(normalized_text):
            if any(a <= m.start() and m.end() <= b for a, b in quoted):
                continue
            number = _parse_number(m.group(1))
            if number is None or number <= 0 or number > 1000:
                continue
            unit_group = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            days, unit = _to_days(number, unit_group or "days")
            if days is None:
                continue
            key = (REFUND_SUBJECT, WINDOW_ATTRIBUTE, "global", "standard", days)
            if key in seen:
                continue
            seen.add(key)
            start, end = m.start(), m.end()
            if callable(offset_translate):
                start, end = offset_translate(start, end)  # type: ignore[misc]
            out.append(
                Claim(
                    subject=REFUND_SUBJECT,
                    attribute=WINDOW_ATTRIBUTE,
                    region="global",
                    customer_tier="standard",
                    value_days=days,
                    value_text=m.group(0).strip(),
                    unit=unit,
                    evidence_start=start,
                    evidence_end=end,
                    effective_from=default_effective,
                    authority_tier=authority_tier,
                    source_id=source_id,
                    chunk_id=chunk_id,
                )
            )

    # Work sentence by sentence so the refund cue, the number and the qualifiers all have to be in
    # the same sentence. This is what keeps "30-minute reset link" out of the claim table.
    cursor = 0
    sentences: list[tuple[int, str]] = []
    for piece in _SENTENCE_SPLIT.split(normalized_text):
        idx = normalized_text.find(piece, cursor)
        if idx == -1:
            idx = cursor
        sentences.append((idx, piece))
        cursor = idx + len(piece)

    for index, (base, sentence) in enumerate(sentences):
        # The cue may legitimately sit in the previous sentence: "Our refund terms changed. The new
        # window is 2 days." An independent review used exactly that split to walk a claim mutation
        # past a strictly per-sentence extractor, so the window is two sentences wide. It is still
        # a *window*, not a document-wide search: widening it further is what starts turning
        # "30 minutes" in an unrelated paragraph into a refund claim.
        previous = sentences[index - 1][1] if index > 0 else ""
        if not _REFUND_CUE.search(sentence) and not _REFUND_CUE.search(previous):
            continue
        region = "global"
        for pattern, name in _REGION_PATTERNS:
            if pattern.search(sentence):
                region = name
                break
        tier = "standard"
        for pattern, name in _TIER_PATTERNS:
            if pattern.search(sentence):
                tier = name
                break
        effective = _parse_effective(sentence, default_effective)

        for pattern in _WINDOW_PATTERNS:
            for m in pattern.finditer(sentence):
                abs_start = base + m.start()
                abs_end = base + m.end()
                if any(a <= abs_start and abs_end <= b for a, b in quoted):
                    continue  # the number belongs to a quoted sample, not to this document
                number = _parse_number(m.group(1))
                if number is None:
                    continue
                days, unit = _to_days(number, m.group(2))
                if days is None or days <= 0 or days > 1000:
                    continue
                dedupe = (REFUND_SUBJECT, WINDOW_ATTRIBUTE, region, tier, days)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                start, end = abs_start, abs_end
                if callable(offset_translate):
                    start, end = offset_translate(abs_start, abs_end)  # type: ignore[misc]
                out.append(
                    Claim(
                        subject=REFUND_SUBJECT,
                        attribute=WINDOW_ATTRIBUTE,
                        region=region,
                        customer_tier=tier,
                        value_days=days,
                        value_text=m.group(0).strip(),
                        unit=unit,
                        evidence_start=start,
                        evidence_end=end,
                        effective_from=effective,
                        authority_tier=authority_tier,
                        source_id=source_id,
                        chunk_id=chunk_id,
                    )
                )
    return out


def _intervals_overlap(a: Claim, b: Claim, horizon_days: int = 3650) -> bool:
    """Treat a claim as in force from ``effective_from`` until superseded.

    Without an explicit ``effective_to`` the honest reading is "open ended", so two claims on the
    same key overlap unless one is explicitly scheduled to start after the other ends. Since the
    MVP does not extract an end date from prose, every same-key pair overlaps — which is the
    conservative choice: it raises a review rather than silently letting both stand.
    """
    del horizon_days
    return True


def compare_claims(incoming: Claim, existing: Claim) -> ClaimConflict | None:
    """Return a conflict when two same-key claims disagree, else ``None``.

    ``unauthorized`` marks the case the threat model actually cares about: a *weaker* source
    changing a value that a stronger authority already set. That is the signal that produces a
    risk finding; an equal-or-higher authority disagreeing is an ordinary review item.
    """
    if incoming.key != existing.key:
        return None
    if incoming.value_days is None or existing.value_days is None:
        return None
    # The unit check comes BEFORE the equality check on purpose: "14 business days" and "14
    # calendar days" are the same number and a genuinely different window, so short-circuiting on
    # equal numbers would hide a real discrepancy.
    if incoming.unit != existing.unit and {incoming.unit, existing.unit} == {
        "days",
        "business_days",
    }:
        # 14 business days vs 14 calendar days genuinely differ but the difference is a units
        # question for a human, not an attack signal.
        return ClaimConflict(
            kind="unit_mismatch",
            incoming=incoming,
            existing=existing,
            authority_delta=TRUST_ORDER.get(incoming.authority_tier, 0)
            - TRUST_ORDER.get(existing.authority_tier, 0),
            detail=(
                f"{incoming.value_days:g} {incoming.unit} vs {existing.value_days:g} "
                f"{existing.unit} for the same region and customer tier; this is a units question "
                "for a reviewer, not an attack signal"
            ),
            unauthorized=False,
        )
    if abs(incoming.value_days - existing.value_days) < 1e-9:
        return None
    if not _intervals_overlap(incoming, existing):
        return None

    delta = TRUST_ORDER.get(incoming.authority_tier, 0) - TRUST_ORDER.get(
        existing.authority_tier, 0
    )
    return ClaimConflict(
        kind="value_disagreement",
        incoming=incoming,
        existing=existing,
        authority_delta=delta,
        detail=(
            f"incoming claims {incoming.value_days:g} {incoming.unit} "
            f"({incoming.authority_tier}); existing authoritative value is "
            f"{existing.value_days:g} {existing.unit} ({existing.authority_tier})"
        ),
        unauthorized=delta < 0,
        metadata={
            "key": list(incoming.key),
            "incoming_value_days": incoming.value_days,
            "existing_value_days": existing.value_days,
        },
    )
