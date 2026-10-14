"""The two HTTP adapters must not diverge.

`apps/api/app/main.py` (FastAPI) is the production adapter; `scripts/serve_dashboard.py` carries a
fallback adapter for environments where FastAPI cannot be installed. Both call the same engine, so
routing is the only thing that can drift — and an independent red-team review found exactly that
drift once: the fallback defaulted the demo-token listing **on** while FastAPI defaulted it **off**,
which handed every tenant's admin bearer token to an unauthenticated caller.

These tests exist so that divergence can never be invisible to CI again.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

pytestmark = pytest.mark.integration


def _fastapi_routes() -> set[tuple[str, str]]:
    """Extract (METHOD, path) pairs from the FastAPI app's decorators without importing FastAPI."""
    source = (ROOT / "apps" / "api" / "app" / "main.py").read_text(encoding="utf-8")
    pairs: set[tuple[str, str]] = set()
    for match in re.finditer(r"@app\.(get|post)\(\s*\"([^\"]+)\"", source):
        pairs.add((match.group(1).upper(), match.group(2)))
    return pairs


def _normalise(path: str) -> str:
    """Collapse path-parameter names so `/x/{id}` and `/x/{chunk_id}` compare equal."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def test_every_fallback_route_exists_in_the_fastapi_app() -> None:
    from serve_dashboard import FALLBACK_ROUTES

    fastapi = {(m, _normalise(p)) for m, p in _fastapi_routes()}
    missing = [
        (method, path)
        for method, path in FALLBACK_ROUTES
        if (method, _normalise(path)) not in fastapi
    ]
    assert not missing, (
        "the fallback adapter serves routes the FastAPI app does not: "
        f"{missing}. Both adapters must expose the same surface."
    )


def test_the_fallback_declares_every_route_it_actually_serves() -> None:
    """A route served but not declared would escape the parity check above."""
    source = (ROOT / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    from serve_dashboard import FALLBACK_ROUTES

    declared = {_normalise(p) for _m, p in FALLBACK_ROUTES}
    served = set(re.findall(r'if path == "(/(?:api|healthz)[^"]*)"', source))
    # `/api/dev/principals` is a deliberate, documented exception: a localhost-only demo
    # convenience that is OFF by default in both adapters and is covered by its own tests below.
    served.discard("/api/dev/principals")
    undeclared = sorted(p for p in served if _normalise(p) not in declared)
    assert not undeclared, f"routes served but not declared in FALLBACK_ROUTES: {undeclared}"


def test_both_adapters_default_the_demo_token_listing_off() -> None:
    """The exact divergence that caused an unauthenticated credential disclosure."""
    fallback = (ROOT / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    fastapi = (ROOT / "apps" / "api" / "app" / "main.py").read_text(encoding="utf-8")

    # Neither adapter may read the flag with a truthy default.
    for name, source in (("fallback", fallback), ("fastapi", fastapi)):
        for match in re.finditer(
            r"environ\.get\(\s*\"MF_DEV_EXPOSE_DEMO_TOKENS\"\s*,\s*\"([^\"]*)\"", source
        ):
            assert match.group(1).strip().lower() not in {"1", "true", "yes", "on"}, (
                f"the {name} adapter defaults MF_DEV_EXPOSE_DEMO_TOKENS to a truthy value; it must "
                "default OFF in both adapters"
            )


def test_the_demo_token_listing_is_off_unless_explicitly_enabled() -> None:
    import serve_dashboard

    previous = os.environ.pop("MF_DEV_EXPOSE_DEMO_TOKENS", None)
    try:
        assert serve_dashboard.demo_tokens_enabled() is False
        assert serve_dashboard.demo_principals() == []
        for truthy in ("1", "true", "YES", "on"):
            os.environ["MF_DEV_EXPOSE_DEMO_TOKENS"] = truthy
            assert serve_dashboard.demo_tokens_enabled() is True
        for falsy in ("0", "false", "", "no"):
            os.environ["MF_DEV_EXPOSE_DEMO_TOKENS"] = falsy
            assert serve_dashboard.demo_tokens_enabled() is False
    finally:
        os.environ.pop("MF_DEV_EXPOSE_DEMO_TOKENS", None)
        if previous is not None:
            os.environ["MF_DEV_EXPOSE_DEMO_TOKENS"] = previous


def test_the_demo_token_listing_is_loopback_only() -> None:
    """Even when enabled it must never hand credentials to a non-loopback client."""
    source = (ROOT / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    assert "client_is_loopback" in source
    assert "if not demo_tokens_enabled() or not self.client_is_loopback" in source


def test_mutating_routes_require_a_token_in_the_fallback() -> None:
    """Every route except health, scenario listing and the gated demo listing resolves a principal."""
    source = (ROOT / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    head = source.split("actor = self._principal(headers)")[0]
    pre_auth = set(re.findall(r'if path == "(/(?:api|healthz)[^"]*)"', head))
    assert pre_auth <= {"/healthz", "/api/dev/principals", "/api/scenarios"}, (
        f"these routes are served before authentication: {sorted(pre_auth)}"
    )
