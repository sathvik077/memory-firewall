"""Content normalisation with a reversible offset map.

Why an offset map: a risk finding must point at the span the *author actually wrote*
(``IMPLEMENTATION_BLUEPRINT.md`` §4.1 — "original byte/character span"). Normalisation that silently
reflows text destroys that. So every normalisation step here is per-character and records, for each
output character, the index of the raw character it came from. Findings detected on normalised text
can therefore be reported in raw coordinates and highlighted in the UI over the original document.

What is normalised, and why:

* ``\\r\\n`` / ``\\r`` → ``\\n`` — line-ending noise.
* Per-character NFKC — folds compatibility forms (e.g. fullwidth Latin) without reflowing the text.
  Applied per character so the map stays exact; a character whose NFKC expansion is longer maps all
  of its outputs back to the same raw index.
* Invisible characters are **removed and recorded**: zero-width space/non-joiner/joiner, BOM, word
  joiner, soft hyphen, bidirectional controls, Unicode tag characters and variation selectors.
  Removing them is what makes ``i\\u200bgnore previous instructions`` detectable as
  ``ignore previous instructions``.
* Confusable letters from Cyrillic/Greek that render like ASCII are mapped to their ASCII skeleton
  and recorded, so ``SYSTEM`` written with a Cyrillic ``Е`` is still matched.

Nothing here is a security decision. Normalisation only produces evidence; ``policy.py`` decides.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

__all__ = [
    "BIDI_CONTROLS",
    "CONFUSABLE_MAP",
    "INVISIBLE_CHARS",
    "NormalizationResult",
    "event_index",
    "normalize_text",
]

#: Characters removed because they are invisible or near-invisible when rendered.
INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
}

#: Bidirectional formatting controls — can visually reorder text to hide an instruction.
BIDI_CONTROLS: dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
    "؜": "ARABIC LETTER MARK",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
}

#: Cyrillic / Greek / full-width letters that render like ASCII letters.
CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ɡ": "g",
    "н": "h",
    "м": "m",
    "т": "t",
    "в": "b",
    "к": "k",
    # Cyrillic uppercase
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "І": "I",
    "Ј": "J",
    "Ѕ": "S",
    "З": "3",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "σ": "o",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "Ζ": "Z",
    # Armenian / Cherokee / mathematical lookalikes seen in the wild
    "օ": "o",
    "Ꭰ": "D",
    "ᴀ": "A",
    "ⅰ": "i",
}

_LINE_ENDINGS = {"\r\n": "\n", "\r": "\n"}


@dataclass(slots=True)
class NormalizationResult:
    """Normalised text plus everything needed to map findings back to the original."""

    raw: str
    normalized: str
    #: ``offset_map[i]`` is the index in :attr:`raw` of ``normalized[i]``.
    offset_map: list[int] = field(default_factory=list)
    report: dict[str, object] = field(default_factory=dict)

    def events(self, key: str) -> list[dict[str, object]]:
        """The per-character normalisation events recorded in :attr:`report` under ``key``.

        :attr:`report` is a JSON-serialisable ``dict[str, object]``, so pulling an event list out
        of it needs a narrowing step. Doing that narrowing once, here, keeps every caller
        statically typed instead of scattering casts across the detector. An absent or
        unexpectedly shaped entry yields an empty list rather than raising, because a malformed
        report must not be able to crash a scan.
        """
        value = self.report.get(key)
        if not isinstance(value, list):
            return []
        return [event for event in value if isinstance(event, dict)]

    def raw_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
        """Translate a half-open normalised span to a half-open raw span.

        An empty normalised span still yields a usable raw anchor so that a finding is never
        reported with a meaningless ``(0, 0)`` span.
        """
        if not self.offset_map:
            return (0, 0)
        norm_start = max(0, min(norm_start, len(self.offset_map) - 1))
        norm_end = max(norm_start + 1, min(norm_end, len(self.offset_map)))
        start = self.offset_map[norm_start]
        end = self.offset_map[norm_end - 1] + 1
        return (start, max(end, start + 1))

    @property
    def had_invisible(self) -> bool:
        return bool(self.report.get("invisible_removed"))

    @property
    def had_bidi(self) -> bool:
        return bool(self.report.get("bidi_removed"))

    @property
    def had_confusables(self) -> bool:
        return bool(self.report.get("confusables_mapped"))


def event_index(event: dict[str, object], default: int = 0) -> int:
    """The ``raw_index`` of a normalisation event, as an int.

    Every event this module writes carries an integer ``raw_index``. The lookup still returns
    ``object`` to a type checker, and a report that has been round-tripped through JSON by a
    caller could carry something else, so an unusable value falls back to ``default`` instead of
    raising mid-scan.
    """
    value = event.get("raw_index", default)
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def normalize_text(raw: str) -> NormalizationResult:
    """Normalise ``raw``, recording every transformation and the raw index of each output char."""
    out: list[str] = []
    omap: list[int] = []
    invisible: list[dict[str, object]] = []
    bidi: list[dict[str, object]] = []
    confusables: list[dict[str, object]] = []
    nfkc_changes = 0
    crlf = 0
    tag_chars: list[dict[str, object]] = []
    variation_selectors = 0

    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]

        # 1. line endings
        two = raw[i : i + 2]
        if two in _LINE_ENDINGS:
            out.append("\n")
            omap.append(i)
            crlf += 1
            i += 2
            continue
        if ch == "\r":
            out.append("\n")
            omap.append(i)
            crlf += 1
            i += 1
            continue

        cp = ord(ch)

        # 2. invisible / formatting characters: drop, but record with the raw index
        if ch in INVISIBLE_CHARS:
            invisible.append(
                {"codepoint": f"U+{cp:04X}", "name": INVISIBLE_CHARS[ch], "raw_index": i}
            )
            i += 1
            continue
        if ch in BIDI_CONTROLS:
            bidi.append({"codepoint": f"U+{cp:04X}", "name": BIDI_CONTROLS[ch], "raw_index": i})
            i += 1
            continue
        # Unicode tag characters (U+E0000..U+E007F) are the "ASCII smuggling" technique: each one
        # is an invisible stand-in for a printable ASCII character. DELETING them would hide the
        # payload from the detector, which is precisely the attack. So the printable range is
        # DECODED back to its ASCII equivalent (U+E0041 -> 'A') and recorded, which makes the
        # smuggled instruction visible to every downstream rule while the offset map still points
        # at the invisible character the author actually wrote.
        if 0xE0020 <= cp <= 0xE007E:
            decoded = chr(cp - 0xE0000)
            tag_chars.append({"codepoint": f"U+{cp:04X}", "raw_index": i, "decoded_to": decoded})
            out.append(decoded)
            omap.append(i)
            i += 1
            continue
        if 0xE0000 <= cp <= 0xE007F:  # language tag / cancel tag: no printable equivalent
            tag_chars.append({"codepoint": f"U+{cp:04X}", "raw_index": i, "decoded_to": None})
            i += 1
            continue
        if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:  # variation selectors
            variation_selectors += 1
            i += 1
            continue
        if unicodedata.category(ch) == "Cf":  # any other format character
            invisible.append(
                {"codepoint": f"U+{cp:04X}", "name": "OTHER FORMAT CHARACTER", "raw_index": i}
            )
            i += 1
            continue

        # 3. confusable → ASCII skeleton
        if ch in CONFUSABLE_MAP:
            mapped = CONFUSABLE_MAP[ch]
            confusables.append(
                {
                    "codepoint": f"U+{cp:04X}",
                    "name": unicodedata.name(ch, "UNKNOWN"),
                    "mapped_to": mapped,
                    "raw_index": i,
                }
            )
            for mc in mapped:
                out.append(mc)
                omap.append(i)
            i += 1
            continue

        # 4. per-character NFKC (keeps the offset map exact)
        folded = unicodedata.normalize("NFKC", ch)
        if folded != ch:
            nfkc_changes += 1
        for fc in folded:
            out.append(fc)
            omap.append(i)
        i += 1

    normalized = "".join(out)
    report: dict[str, object] = {
        "original_length": n,
        "normalized_length": len(normalized),
        "line_endings_normalized": crlf,
        "nfkc_character_changes": nfkc_changes,
        "invisible_removed": invisible,
        "bidi_removed": bidi,
        "tag_characters_decoded": tag_chars,
        "variation_selectors_removed": variation_selectors,
        "confusables_mapped": confusables,
        "steps": [
            "line_ending_normalization",
            "invisible_character_removal",
            "bidi_control_removal",
            "unicode_tag_decoding",
            "confusable_folding",
            "per_character_nfkc",
        ],
    }
    return NormalizationResult(raw=raw, normalized=normalized, offset_map=omap, report=report)
