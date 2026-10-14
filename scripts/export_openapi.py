#!/usr/bin/env python3
"""Write the OpenAPI document to docs/openapi.json.

Uses FastAPI's generator when FastAPI is installed. When it is not, it emits a hand-maintained
document built from the fallback adapter's route table, clearly marked as such, so the HTTP surface
is still documented rather than simply missing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "packages" / "memory_firewall", ROOT / "apps" / "api", ROOT / "scripts", ROOT):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

OUT = ROOT / "docs" / "openapi.json"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    try:
        from app.main import create_app

        schema = create_app().openapi()
        schema["info"]["x-generated-by"] = "fastapi"
        OUT.write_text(json.dumps(schema, indent=2), encoding="utf-8")
        print(
            f"wrote {OUT.relative_to(ROOT)} ({len(schema.get('paths', {}))} paths) from the FastAPI app"
        )
        return 0
    except ModuleNotFoundError:
        pass

    from memory_firewall._version import __version__
    from serve_dashboard import FALLBACK_ROUTES

    paths: dict[str, dict] = {}
    for method, path in FALLBACK_ROUTES:
        entry = paths.setdefault(path, {})
        entry[method.lower()] = {
            "summary": f"{method} {path}",
            "security": [] if path == "/healthz" else [{"bearerAuth": []}],
            "responses": {
                "200": {"description": "OK"},
                "401": {"description": "authentication required"},
                "403": {"description": "forbidden"},
                "404": {"description": "not found"},
            },
        }
    schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "Memory Firewall API",
            "version": __version__,
            "x-generated-by": "fallback route table",
            "description": (
                "GENERATED WITHOUT FASTAPI. This environment could not install FastAPI, so this "
                "document lists the routes the fallback adapter serves rather than FastAPI's full "
                "generated schema with request/response models. Re-run `make openapi` after "
                "`uv sync --extra dev` for the complete document."
            ),
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": paths,
    }
    OUT.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(paths)} paths) from the fallback route table")
    print("NOTE: FastAPI is not installed, so this is the reduced document.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
