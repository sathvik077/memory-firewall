"""Safe rendering of untrusted chunk text.

Quarantined content is attacker-controlled by definition, and a reviewer has to *look* at it to
review it. That makes the preview path a real injection surface (MF-23, MF-SEED-10), so escaping
lives here in the engine rather than being left to the UI: the API serves an already-escaped
``preview_html`` alongside the raw text, and the dashboard renders text nodes only (no
``dangerouslySetInnerHTML``) — two independent layers, either of which would be sufficient.

:func:`highlight_spans` escapes first and only then inserts ``<mark>`` elements at byte offsets
translated through the escaping, so an evidence span can be highlighted over hostile input without
ever concatenating unescaped attacker text into markup.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

__all__ = ["escape_preview", "highlight_spans", "truncate_preview"]

MAX_PREVIEW_CHARS = 1200


def truncate_preview(text: str, limit: int = MAX_PREVIEW_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def escape_preview(text: str, limit: int = MAX_PREVIEW_CHARS) -> str:
    """HTML-escape untrusted text, including quotes, and make invisible characters visible.

    Zero-width and bidi characters are replaced with a visible ``U+XXXX`` token: a reviewer who
    cannot see the payload cannot review it, and leaving a bidi override in a reviewer's browser
    would let the attacker reorder what the reviewer reads.
    """
    from .normalize import BIDI_CONTROLS, INVISIBLE_CHARS

    out: list[str] = []
    for ch in truncate_preview(text, limit):
        if ch in INVISIBLE_CHARS or ch in BIDI_CONTROLS or 0xE0000 <= ord(ch) <= 0xE007F:
            out.append(f"␉U+{ord(ch):04X}␊")
        else:
            out.append(ch)
    return escape("".join(out), quote=True)


def highlight_spans(
    text: str, spans: Sequence[tuple[int, int]], limit: int = MAX_PREVIEW_CHARS
) -> str:
    """Return escaped HTML with ``<mark>`` around each span. Escaping always happens first."""
    clipped = truncate_preview(text, limit)
    bounded = sorted(
        {(max(0, s), min(len(clipped), e)) for s, e in spans if e > s and s < len(clipped)}
    )
    if not bounded:
        return escape_preview(clipped, limit)

    merged: list[tuple[int, int]] = []
    for start, end in bounded:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.append(escape_preview(clipped[cursor:start], limit))
        parts.append('<mark class="mf-evidence">')
        parts.append(escape_preview(clipped[start:end], limit))
        parts.append("</mark>")
        cursor = end
    parts.append(escape_preview(clipped[cursor:], limit))
    return "".join(parts)
