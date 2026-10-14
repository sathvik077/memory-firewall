"""Time handling.

Everything is UTC and ISO-8601 with a ``Z`` suffix, stored as TEXT so that SQLite string comparison
is a correct chronological comparison. A fixed clock is injectable so the demo and the seed-vector
harness are deterministic (``CLAUDE.md`` §0: fixed demo timestamps).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

__all__ = [
    "END_OF_TIME",
    "fixed_clock",
    "iso",
    "now",
    "now_iso",
    "parse",
    "to_utc",
]

# Sentinel used only for human-readable rendering of an open interval; never written to the DB,
# where an open interval is represented by SQL NULL.
END_OF_TIME = "9999-12-31T23:59:59Z"

_FIXED: datetime | None = None


def now() -> datetime:
    """Current UTC time, or the injected fixed instant."""
    if _FIXED is not None:
        return _FIXED
    return datetime.now(tz=UTC)


def now_iso() -> str:
    return iso(now())


def to_utc(value: datetime) -> datetime:
    """Coerce to timezone-aware UTC. A naive datetime is *assumed* UTC and documented as such."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def iso(value: datetime) -> str:
    """Render as ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — lexicographically sortable."""
    return to_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def parse(value: str | datetime) -> datetime:
    """Parse an ISO-8601 instant, tolerating a trailing ``Z``."""
    if isinstance(value, datetime):
        return to_utc(value)
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return to_utc(datetime.fromisoformat(text))


@contextmanager
def fixed_clock(instant: str | datetime) -> Iterator[datetime]:
    """Freeze :func:`now` for the duration of the block (tests, seeding, demo reproducibility)."""
    global _FIXED
    previous = _FIXED
    _FIXED = parse(instant)
    try:
        yield _FIXED
    finally:
        _FIXED = previous
