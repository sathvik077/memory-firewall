"""The adversarial fixtures must never be reachable from a request handler.

``memory_firewall.testing`` deliberately writes poison into the live index with raw SQL. That is
only safe as long as nothing an HTTP caller can reach imports it. This test enforces that by
inspection, so a future refactor cannot quietly expose it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "apps" / "api"
PACKAGE = ROOT / "packages" / "memory_firewall" / "memory_firewall"

#: Modules allowed to import the adversarial fixtures.
ALLOWED = {"scenarios.py", "testing.py"}


def test_the_api_never_imports_the_adversarial_fixtures() -> None:
    offenders = []
    for path in API.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"\b(?:from|import)\b[^\n]*\btesting\b", text):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"the API imports the test-only fixtures: {offenders}"


def test_only_allow_listed_engine_modules_import_the_fixtures() -> None:
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if path.name in ALLOWED:
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(
            r"from\s+\.\s*testing\b|from\s+\.\s+import\s+testing\b|import\s+testing\b", text
        ):
            offenders.append(path.name)
    assert not offenders, f"unexpected modules import the adversarial fixtures: {offenders}"


def test_the_sdk_does_not_re_export_the_fixtures() -> None:
    import memory_firewall

    assert not hasattr(memory_firewall, "inject_index_poison")
    assert not hasattr(memory_firewall, "mutate_chunk_text_after_index")
    assert "testing" not in memory_firewall.__all__


def test_the_unguarded_baseline_is_disabled_by_default() -> None:
    from memory_firewall.config import FirewallConfig

    assert FirewallConfig().enable_unguarded_baseline is False


def test_the_unguarded_baseline_requires_admin_and_the_flag(guarded_world) -> None:
    from memory_firewall.errors import AuthorizationError

    engine = guarded_world.engine
    with pytest.raises(AuthorizationError, match="disabled"):
        engine.unguarded_baseline(guarded_world.root, query="refund")
    engine.config.enable_unguarded_baseline = True
    with pytest.raises(AuthorizationError):
        engine.unguarded_baseline(guarded_world.reader, query="refund")
    payload = engine.unguarded_baseline(guarded_world.root, query="refund")
    assert payload["is_memory_firewall_output"] is False
    assert "not a Memory Firewall retrieval result" in payload["warning"]


def test_no_cross_request_cache_exists_in_the_retrieval_path() -> None:
    """The MVP's chosen answer to cache-invalidation bugs is to have no cache. Enforced here."""
    text = (PACKAGE / "retrieval.py").read_text(encoding="utf-8")
    engine_text = (PACKAGE / "engine.py").read_text(encoding="utf-8")
    for needle in ("lru_cache", "cached_property", "functools.cache", "@cache"):
        assert needle not in text, f"{needle} appeared in the retrieval guard"
        assert needle not in engine_text, f"{needle} appeared in the engine"


def test_the_guard_sql_contains_every_required_predicate() -> None:
    """A structural check that no predicate is quietly dropped from the single guarded query."""
    from memory_firewall.retrieval import _GUARDED_SQL

    required = [
        "s.tenant_id = :tenant",
        "s.status    = 'active'",
        "acl.principal_id = :principal",
        "acl.permission = 'read'",
        "d.status    = 'active'",
        "c.state     = 'active'",
        "vv.state    = 'active'",
        "vv.system_recorded_from <= :as_of_recorded",
        "vv.effective_from <= :as_of_valid",
        "fts_chunks MATCH :fts",
    ]
    for predicate in required:
        assert predicate in _GUARDED_SQL, f"missing guard predicate: {predicate}"
