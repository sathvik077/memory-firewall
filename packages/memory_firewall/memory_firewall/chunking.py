"""Deterministic chunking that preserves raw-document offsets.

Chunks are the unit of state, ACL and retrieval, so the boundary rule has to be stable: identical
input must always produce identical chunk boundaries, or a re-ingestion would look like a content
change and the resurrection test (Scenario E) would be meaningless.

Boundaries are chosen on paragraph breaks first, then sentence ends, then a hard character cap. Each
chunk carries both the raw slice (what the author wrote — shown in previews, HTML-escaped by the UI)
and the normalised slice (what is indexed and scanned).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import NormalizationResult

__all__ = ["ChunkSpan", "chunk_normalized"]

_PARAGRAPH = re.compile(r"\n\s*\n")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


@dataclass(slots=True)
class ChunkSpan:
    ordinal: int
    norm_start: int
    norm_end: int
    raw_start: int
    raw_end: int
    normalized_text: str
    raw_text: str


def _split_paragraphs(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    pos = 0
    for m in _PARAGRAPH.finditer(text):
        if m.start() > pos:
            spans.append((pos, m.start()))
        pos = m.end()
    if pos < len(text):
        spans.append((pos, len(text)))
    return spans or [(0, len(text))]


def _split_long(text: str, start: int, end: int, max_chars: int) -> list[tuple[int, int]]:
    """Split an over-long span on sentence ends, falling back to a hard cap."""
    if end - start <= max_chars:
        return [(start, end)]
    pieces: list[tuple[int, int]] = []
    cursor = start
    segment = text[start:end]
    # candidate cut points in absolute coordinates
    cuts = [start + m.start() for m in _SENTENCE_END.finditer(segment)] + [end]
    for cut in cuts:
        if cut - cursor >= max_chars:
            # walk forward through sentence cuts until the piece is as large as allowed
            piece_end = cursor
            for c in cuts:
                if cursor < c <= cursor + max_chars:
                    piece_end = c
            if piece_end <= cursor:  # a single sentence longer than the cap
                piece_end = min(cursor + max_chars, end)
            pieces.append((cursor, piece_end))
            cursor = piece_end
    if cursor < end:
        while end - cursor > max_chars:
            pieces.append((cursor, cursor + max_chars))
            cursor += max_chars
        pieces.append((cursor, end))
    return [(a, b) for a, b in pieces if b > a]


def chunk_normalized(result: NormalizationResult, max_chars: int = 900) -> list[ChunkSpan]:
    """Chunk the normalised text, mapping every boundary back to raw coordinates."""
    text = result.normalized
    if not text.strip():
        return []

    spans: list[tuple[int, int]] = []
    for p_start, p_end in _split_paragraphs(text):
        spans.extend(_split_long(text, p_start, p_end, max_chars))

    chunks: list[ChunkSpan] = []
    ordinal = 0
    for norm_start, norm_end in spans:
        piece = text[norm_start:norm_end]
        if not piece.strip():
            continue
        # trim surrounding whitespace while keeping offsets honest
        lead = len(piece) - len(piece.lstrip())
        trail = len(piece) - len(piece.rstrip())
        s = norm_start + lead
        e = norm_end - trail
        if e <= s:
            continue
        raw_start, raw_end = result.raw_span(s, e)
        chunks.append(
            ChunkSpan(
                ordinal=ordinal,
                norm_start=s,
                norm_end=e,
                raw_start=raw_start,
                raw_end=raw_end,
                normalized_text=text[s:e],
                raw_text=result.raw[raw_start:raw_end],
            )
        )
        ordinal += 1
    return chunks
