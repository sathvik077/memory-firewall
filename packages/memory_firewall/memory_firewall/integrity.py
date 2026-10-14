"""Integrity manifests held in a side store.

``IMPLEMENTATION_BLUEPRINT.md`` §2 is explicit: a SHA-256 digest only proves consistency *with a
separately protected expected value*. If the attacker controls both the content and the expected
digest, the digest proves nothing. So the expected digests do not live in the content database:
they live in a sibling SQLite file ``<db>.manifests``, and when ``MF_HMAC_KEY`` is set they are
HMACs under a key that is never written to either file.

What this actually buys, stated precisely:

* **Detected:** post-index mutation of ``chunks.text`` / ``chunks.normalized_text`` in the content
  DB (the Scenario in MF-SEED-11), including a mutation performed with direct SQL that bypasses the
  application. A mismatched chunk is excluded from retrieval and raises an integrity alert.
* **Not detected:** an attacker with write access to the manifest store as well; an attacker who
  replaces both files; anything outside the instrumented pipeline. This is application-level
  tamper *evidence*, not tamper *proofing*, and ``docs/SECURITY.md`` says so.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from pathlib import Path

from .clock import now_iso
from .ids import constant_time_eq, sha256_hex, stable_hmac

__all__ = ["ManifestStore", "manifest_path_for"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS manifests (
    key        TEXT PRIMARY KEY,
    digest     TEXT NOT NULL,
    algo       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def manifest_path_for(db_path: str | Path) -> Path:
    return Path(f"{db_path}.manifests")


class ManifestStore:
    """Expected-digest side store. Deliberately a different file from the content DB."""

    def __init__(self, db_path: str | Path, hmac_key: bytes | None = None) -> None:
        self.path = manifest_path_for(db_path)
        self.hmac_key = hmac_key
        self.algo = "hmac-sha256" if hmac_key else "sha256"
        if str(db_path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    # -- internals ---------------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def digest(self, payload: str | bytes) -> str:
        if self.hmac_key:
            return stable_hmac(self.hmac_key, payload)
        return sha256_hex(payload)

    # -- API ---------------------------------------------------------------------------------
    def put(self, key: str, payload: str | bytes) -> str:
        d = self.digest(payload)
        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO manifests(key, digest, algo, created_at, updated_at)"
                " VALUES(?,?,?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET digest=excluded.digest,"
                " algo=excluded.algo, updated_at=excluded.updated_at",
                (key, d, self.algo, ts, ts),
            )
        return d

    def put_many(self, items: Iterable[tuple[str, str | bytes]]) -> dict[str, str]:
        ts = now_iso()
        out: dict[str, str] = {}
        rows = []
        for key, payload in items:
            d = self.digest(payload)
            out[key] = d
            rows.append((key, d, self.algo, ts, ts))
        if rows:
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO manifests(key, digest, algo, created_at, updated_at)"
                    " VALUES(?,?,?,?,?)"
                    " ON CONFLICT(key) DO UPDATE SET digest=excluded.digest,"
                    " algo=excluded.algo, updated_at=excluded.updated_at",
                    rows,
                )
        return out

    def get(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT digest FROM manifests WHERE key = ?", (key,)).fetchone()
        return row["digest"] if row else None

    def get_many(self, keys: Sequence[str]) -> dict[str, str]:
        if not keys:
            return {}
        placeholders = ",".join("?" * len(keys))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT key, digest FROM manifests WHERE key IN ({placeholders})",  # noqa: S608
                tuple(keys),
            ).fetchall()
        return {r["key"]: r["digest"] for r in rows}

    def verify(self, key: str, payload: str | bytes) -> bool:
        """Constant-time comparison. A missing manifest is a FAILURE, never a pass."""
        expected = self.get(key)
        if expected is None:
            return False
        return constant_time_eq(expected, self.digest(payload))

    def delete(self, key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM manifests WHERE key = ?", (key,))

    def delete_prefix(self, prefix: str) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM manifests WHERE key LIKE ?", (f"{prefix}%",))
            return cur.rowcount

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM manifests").fetchone()["n"])

    @staticmethod
    def chunk_key(chunk_id: str) -> str:
        return f"chunk:{chunk_id}"

    @staticmethod
    def version_key(version_id: str) -> str:
        return f"version:{version_id}"
