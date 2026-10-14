"""Database access.

Three deliberate choices:

1. **A connection per transaction.** No pooled, long-lived, shared connection and therefore no
   cross-request result cache anywhere in the MVP (``IMPLEMENTATION_BLUEPRINT.md`` §3: "no
   cross-request result cache is easiest and preferred"). A revoked ACL takes effect on the very
   next query because there is nothing to invalidate.
2. **FTS5 is asserted, never emulated.** ``make setup`` and engine construction both fail loudly
   with build instructions if the interpreter's SQLite lacks FTS5. Silently substituting canned
   answers for real retrieval is explicitly forbidden by the contract.
3. **Writes use ``BEGIN IMMEDIATE``** so that a chunk-state change and its FTS index change either
   both land or neither does; ``tests/integration/test_transactions.py`` asserts the rollback path.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from ._version import SCHEMA_VERSION
from .clock import now_iso
from .errors import FirewallError

__all__ = ["Database", "FTS5Unavailable", "load_schema_sql"]

_FTS5_HELP = """\
This interpreter's SQLite build has no FTS5 module, so Memory Firewall cannot perform real lexical
retrieval. It will not fall back to canned answers.

Fixes:
  * Debian/Ubuntu : apt-get install -y libsqlite3-0 sqlite3  (then reinstall Python, or use uv's
                    managed CPython: `uv python install 3.12`)
  * macOS (brew)  : brew install sqlite && reinstall Python against it
  * Windows       : use WSL2, or a python.org build (FTS5 is enabled by default)
Check with:
  python -c "import sqlite3;sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')"
"""


class FTS5Unavailable(FirewallError):
    status_code = 500
    code = "fts5_unavailable"


def load_schema_sql() -> str:
    """Read ``schema.sql`` from the installed package (works from a wheel as well as a checkout)."""
    return resources.files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")


def assert_fts5(conn: sqlite3.Connection | None = None) -> None:
    owned = conn is None
    conn = conn or sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _mf_fts5_probe USING fts5(x)")
        conn.execute("DROP TABLE IF EXISTS _mf_fts5_probe")
    except sqlite3.OperationalError as exc:  # pragma: no cover - environment dependent
        raise FTS5Unavailable(_FTS5_HELP) from exc
    finally:
        if owned:
            conn.close()


class Database:
    """Thin SQLite wrapper. Holds no state that could become stale between requests."""

    def __init__(self, path: str | Path, *, timeout: float = 20.0) -> None:
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self.timeout = timeout
        self._memory_conn: sqlite3.Connection | None = None
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- connections -------------------------------------------------------------------------
    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if str(self.path) != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 15000")
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """A read connection. In-memory databases reuse one connection (they cannot be shared)."""
        if str(self.path) == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = self._new_connection()
            yield self._memory_conn
            return
        conn = self._new_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Write transaction. Commits on success, rolls back on any exception."""
        if str(self.path) == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = self._new_connection()
            conn = self._memory_conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
            return

        conn = self._new_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    # -- lifecycle ---------------------------------------------------------------------------
    def migrate(self) -> None:
        """Create or upgrade the schema. Idempotent."""
        sql = load_schema_sql()
        with self.connect() as conn:
            assert_fts5(conn)
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (SCHEMA_VERSION,),
            )
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('initialized_at', ?)"
                " ON CONFLICT(key) DO NOTHING",
                (now_iso(),),
            )

    def schema_version(self) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        return row["value"] if row else None

    def exists(self) -> bool:
        return str(self.path) == ":memory:" or self.path.exists()

    def close(self) -> None:
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None

    # -- small helpers used across the engine ------------------------------------------------
    @staticmethod
    def one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return conn.execute(sql, params).fetchone()

    @staticmethod
    def all(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return conn.execute(sql, params).fetchall()
