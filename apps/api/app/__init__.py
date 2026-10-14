"""Memory Firewall HTTP API (FastAPI)."""

from __future__ import annotations

__all__ = ["create_app"]


def create_app():
    from .main import create_app as _factory

    return _factory()
