"""MF-23: input bounds, query injection, importer path safety, and no SSRF surface."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tests.conftest import World

from memory_firewall.adapters.directory import DirectoryAdapter
from memory_firewall.config import FirewallConfig
from memory_firewall.engine import MemoryFirewallEngine
from memory_firewall.errors import PolicyError, ValidationError
from memory_firewall.retrieval import build_fts_query

pytestmark = pytest.mark.security


def test_oversized_documents_are_refused(world: World) -> None:
    engine = MemoryFirewallEngine(
        world.engine.config.db_path,
        config=FirewallConfig(db_path=world.engine.config.db_path, max_document_bytes=1024),
    )
    with pytest.raises(ValidationError, match="exceeds"):
        engine.ingest(world.admin, source_id="issues", text="x" * 2048)


@pytest.mark.parametrize("text", ["", "   ", "\n\n\t"])
def test_empty_documents_are_refused(world: World, text: str) -> None:
    with pytest.raises(ValidationError):
        world.engine.ingest(world.admin, source_id="issues", text=text)


def test_ingest_into_a_revoked_source_is_refused(guarded_world: World) -> None:
    engine = guarded_world.engine
    engine.revoke_source(guarded_world.admin, "issues", "retired")
    with pytest.raises(PolicyError, match="revoked"):
        engine.ingest(guarded_world.admin, source_id="issues", text="Refund note.")


def test_an_unknown_trust_tier_is_refused(world: World) -> None:
    with pytest.raises(ValidationError):
        world.engine.create_source(world.root, "bad", trust_tier="super_authoritative")


def test_retrieve_limit_is_clamped(guarded_world: World) -> None:
    engine = guarded_world.engine
    for i in range(40):
        engine.ingest(guarded_world.admin, source_id="wiki", text=f"Refund note {i} body text.")
    result = engine.retrieve(guarded_world.reader, query="refund note", limit=10_000)
    assert len(result.context_chunks) <= engine.config.max_retrieve_limit


@pytest.mark.parametrize(
    "hostile",
    [
        '"); DROP TABLE chunks; --',
        "' OR 1=1 --",
        "NEAR/3 refund",
        'refund" OR fts_chunks MATCH "*',
        "^refund",
        "refund*" * 200,
        "(((((refund",
        "\x00refund",
        "refund\n\r\t",
        "{}[]()<>|&;",
    ],
)
def test_hostile_queries_cannot_break_or_widen_the_search(
    guarded_world: World, hostile: str
) -> None:
    """User text is never interpolated into FTS5 syntax, so these are inert."""
    engine = guarded_world.engine
    result = engine.retrieve(guarded_world.reader, query=hostile)
    assert result.guard_enforced is True
    assert result.fail_closed is False
    assert all(c.source_id == "policy" for c in result.context_chunks)
    with engine.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"] >= 1


def test_the_fts_query_builder_quotes_every_token() -> None:
    assert build_fts_query('"); DROP TABLE chunks; --') == '"drop" OR "table" OR "chunks"'
    assert build_fts_query("") == ""
    assert build_fts_query("!!!") == ""
    assert '"' in build_fts_query('he said "refund"')


def test_directory_importer_refuses_a_path_outside_the_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("credentials: hunter2", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.md").write_text("Refund policy notes.", encoding="utf-8")

    adapter = DirectoryAdapter(root)
    names = [d.relative_path for d in adapter.iter_documents()]
    assert names == ["ok.md"]


def test_directory_importer_skips_symlinked_files_and_directories(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "token.md").write_text("api key", encoding="utf-8")
    secret_file = tmp_path / "passwd.md"
    secret_file.write_text("root:x:0:0", encoding="utf-8")

    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.md").write_text("Refund policy notes.", encoding="utf-8")
    try:
        os.symlink(secret_file, root / "link.md")
        os.symlink(secret_dir, root / "linkdir")
    except (OSError, NotImplementedError):  # pragma: no cover - platform without symlinks
        pytest.skip("symlinks unavailable on this platform")

    adapter = DirectoryAdapter(root)
    names = [d.relative_path for d in adapter.iter_documents()]
    assert names == ["ok.md"]
    reasons = {s["reason"] for s in adapter.skipped}
    assert "symlink_skipped" in reasons


def test_directory_importer_ignores_dependency_and_secret_directories(tmp_path: Path) -> None:
    root = tmp_path / "root"
    for name in (".git", "node_modules", ".venv", "private", ".ssh"):
        (root / name).mkdir(parents=True)
        (root / name / "leak.md").write_text("secret", encoding="utf-8")
    (root / "keep.md").write_text("Refund notes.", encoding="utf-8")
    adapter = DirectoryAdapter(root)
    assert [d.relative_path for d in adapter.iter_documents()] == ["keep.md"]


def test_directory_importer_enforces_suffix_and_size(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "keep.md").write_text("Refund notes.", encoding="utf-8")
    (root / "skip.exe").write_text("binary-ish", encoding="utf-8")
    (root / "big.md").write_text("x" * 5000, encoding="utf-8")
    adapter = DirectoryAdapter(root, max_bytes_per_file=1000)
    names = [d.relative_path for d in adapter.iter_documents()]
    assert names == ["keep.md"]
    reasons = {s["reason"] for s in adapter.skipped}
    assert {"suffix_not_allowed", "file_too_large"} <= reasons


def test_directory_importer_requires_an_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        DirectoryAdapter(tmp_path / "nope")
    f = tmp_path / "a-file.md"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError):
        DirectoryAdapter(f)


def test_there_is_no_url_ingestion_path_anywhere(tmp_path: Path) -> None:
    """No SSRF surface can exist if no code path fetches a URL. Asserted by inspection."""
    import re

    package = Path(__file__).resolve().parents[2] / "packages" / "memory_firewall"
    api = Path(__file__).resolve().parents[2] / "apps" / "api"
    offenders: list[str] = []
    pattern = re.compile(
        r"\b(?:requests\.(?:get|post)|urllib\.request|urlopen|httpx\.(?:get|post|Client)"
        r"|aiohttp|socket\.create_connection)\b"
    )
    for path in [*package.rglob("*.py"), *api.rglob("*.py")]:
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            offenders.append(f"{path.name}:{line}: {match.group(0)}")
    assert not offenders, f"an outbound-request call appeared in the engine or API: {offenders}"
