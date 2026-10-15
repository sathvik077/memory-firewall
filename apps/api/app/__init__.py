"""Memory Firewall HTTP API (FastAPI)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only for the annotation
    from fastapi import FastAPI

__all__ = ["create_app"]


def create_app() -> FastAPI:
    """Build the FastAPI application.

    FastAPI is imported lazily so that importing this package stays cheap and so the engine and
    its test suites remain usable in an environment where FastAPI is not installed.
    """
    from .main import create_app as _factory

    return _factory()
