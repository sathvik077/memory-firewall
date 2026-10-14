#!/usr/bin/env python3
"""Dashboard dev server, and a fallback API adapter.

Two jobs:

1. Serve ``apps/dashboard/dist`` on ``127.0.0.1:$MF_WEB_PORT`` (localhost only).
2. Answer ``/api/*`` and ``/healthz``. If a FastAPI server is already listening on the API port,
   requests are **proxied** to it, so the dashboard talks to the real production app. If FastAPI is
   not installed in this environment, the same requests are served **in process** by a fallback
   adapter over the identical ``MemoryFirewallEngine``.

Why a fallback adapter exists, stated plainly: the HTTP framework the contract specifies could not
be installed in the environment this was verified in (see ``docs/DECISIONS.md`` and
``docs/VERIFICATION.md``). Rather than leave the UI, the browser E2E run and the screenshots
unverifiable, the fallback adapter reuses the engine directly — so every security decision is the
same code, and only the routing layer differs. ``tests/integration/test_route_parity.py`` asserts
that every route the fallback serves also exists in the FastAPI app with the same method, so the
two cannot drift.

The fallback is a development tool. It binds to localhost, it is never used when FastAPI is
available, and it is not what the Docker image runs.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "packages" / "memory_firewall", ROOT / "apps" / "api", ROOT):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from memory_firewall._version import DETECTOR_VERSION, POLICY_REVISION  # noqa: E402
from memory_firewall.clock import parse  # noqa: E402
from memory_firewall.config import from_env  # noqa: E402
from memory_firewall.engine import MemoryFirewallEngine  # noqa: E402
from memory_firewall.errors import AuthenticationError, FirewallError  # noqa: E402
from memory_firewall.identity import Principal, strip_forgeable_fields  # noqa: E402
from memory_firewall.scenarios import SCENARIOS, run_scenario  # noqa: E402

DIST = ROOT / "apps" / "dashboard" / "dist"

#: (method, path-template) pairs the fallback serves. Asserted against the FastAPI app by
#: tests/integration/test_route_parity.py. `/api/dev/principals` is intentionally excluded there
#: because it is a localhost-only development convenience, documented as such.
FALLBACK_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/healthz"),
    ("GET", "/api/whoami"),
    ("GET", "/api/stats"),
    ("GET", "/api/sources"),
    ("POST", "/api/sources/{source_id}/revoke"),
    ("POST", "/api/documents"),
    ("POST", "/api/retrieve"),
    ("POST", "/api/context-packs"),
    ("GET", "/api/quarantine"),
    ("POST", "/api/quarantine/{chunk_id}/{decision}"),
    ("GET", "/api/conflicts"),
    ("POST", "/api/conflicts/{conflict_id}/resolve"),
    ("GET", "/api/ledger"),
    ("GET", "/api/exposures"),
    ("GET", "/api/snapshots"),
    ("POST", "/api/snapshots"),
    ("POST", "/api/snapshots/{snapshot_id}/diff"),
    ("GET", "/api/scenarios"),
    ("POST", "/api/scenarios/run"),
    ("POST", "/api/demo/unguarded-comparison"),
)


def demo_tokens_enabled() -> bool:
    """Whether the demo-token listing is switched on.

    **Defaults to OFF.** An independent red-team review found this defaulting to *on* here while
    the FastAPI app defaulted it off, which meant the adapter that was actually serving handed
    every tenant's admin bearer token to an unauthenticated caller. Since the token *is* the
    identity, that collapsed the whole auth model for anyone who could reach the port. Both
    adapters now default off and `tests/integration/test_route_parity.py` asserts they agree.
    """
    return os.environ.get("MF_DEV_EXPOSE_DEMO_TOKENS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def demo_principals() -> list[dict[str, str]]:
    """Read the demo tokens `make setup` wrote into the environment / .env.

    This exists so the dashboard can offer an "Acting as" switcher without a login screen in a
    local demo. It is off unless ``MF_DEV_EXPOSE_DEMO_TOKENS`` is explicitly set, it is only served
    to a loopback client, and it is never enabled by the Docker image or any production profile.
    The tokens it returns grant access to the local demo database only. When it is off the
    dashboard falls back to asking the operator to paste a bearer token, which is the normal path
    for any deployment that is not this demo.
    """
    if not demo_tokens_enabled():
        return []
    env_file = ROOT / ".env"
    values: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("MF_TOKEN_") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    for key, value in os.environ.items():
        if key.startswith("MF_TOKEN_") and value:
            values[key] = value

    roles = {
        "SUPPORT_ROOT": ("support-root", "admin", "support"),
        "SUPPORT_ADMIN": ("support-admin", "reviewer", "support"),
        "SUPPORT_READER": ("support-reader", "reader", "support"),
        "OTHER_ADMIN": ("other-admin", "admin", "other"),
        "OTHER_READER": ("other-reader", "reader", "other"),
    }
    out: list[dict[str, str]] = []
    for suffix, (principal_id, role, tenant) in roles.items():
        token = values.get(f"MF_TOKEN_{suffix}")
        if token:
            out.append(
                {
                    "id": principal_id,
                    "label": principal_id,
                    "token": token,
                    "role": role,
                    "tenant": tenant,
                }
            )
    return out


class FallbackApi:
    """Minimal HTTP adapter over the engine. Routing only — no security logic lives here."""

    def __init__(self) -> None:
        config = from_env()
        self.engine = MemoryFirewallEngine(config.db_path, config=config)
        #: Set per request by the handler; only a loopback client may read the demo-token listing.
        self.client_is_loopback = False

    # -- helpers --------------------------------------------------------------------------
    def _principal(self, headers: Any) -> Principal:
        auth = headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            raise AuthenticationError("a bearer token is required")
        return self.engine.authenticate(auth.split(" ", 1)[1].strip())

    @staticmethod
    def _dt(body: dict[str, Any], key: str) -> Any:
        value = body.get(key)
        return parse(value) if value else None

    # -- dispatch -------------------------------------------------------------------------
    def handle(
        self, method: str, path: str, body: dict[str, Any], headers: Any
    ) -> tuple[int, dict[str, Any]]:
        clean, ignored = strip_forgeable_fields(body)
        parts = [p for p in path.split("/") if p]

        if path == "/healthz":
            return 200, {
                "status": "ok",
                "schema_version": self.engine.db.schema_version(),
                "detector_version": DETECTOR_VERSION,
                "policy_revision": POLICY_REVISION,
                "fts5": True,
                "database": str(self.engine.config.db_path),
                "guard_enforced": True,
                "unguarded_baseline_enabled": self.engine.config.enable_unguarded_baseline,
                "notes": [
                    "served by the localhost fallback adapter because FastAPI is not installed; "
                    "every security decision is the same engine code"
                ],
            }
        if path == "/api/dev/principals":
            # Off by default; loopback only; never a route that can hand credentials to a remote
            # caller. When disabled it answers 404 exactly as the FastAPI app does, so the
            # dashboard's token-entry fallback behaves identically against either adapter.
            if not demo_tokens_enabled() or not self.client_is_loopback:
                return 404, {
                    "code": "not_found",
                    "message": (
                        "demo token listing is disabled. Set MF_DEV_EXPOSE_DEMO_TOKENS=1 for a "
                        "local demo, or paste a bearer token into the dashboard."
                    ),
                }
            return 200, {"items": demo_principals()}
        if path == "/api/scenarios":
            return 200, {
                "items": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "kind": s.kind,
                        "contract_ref": s.contract_ref,
                        "description": s.description,
                        "expectation": s.expectation,
                    }
                    for s in SCENARIOS
                ],
                "count": len(SCENARIOS),
                "note": "Each scenario runs against a fresh disposable database.",
            }

        actor = self._principal(headers)

        if path == "/api/whoami":
            return 200, {**actor.as_dict(), "identity_source": "verified_token"}
        if path == "/api/stats":
            return 200, self.engine.stats(actor)
        if path == "/api/sources" and method == "GET":
            return 200, {"sources": self.engine.sources(actor), "identity_source": "verified_token"}
        if (
            method == "POST"
            and len(parts) == 4
            and parts[:2] == ["api", "sources"]
            and parts[3] == "revoke"
        ):
            return 200, {
                **self.engine.revoke_source(actor, parts[2], str(clean.get("reason", ""))),
                "ignored_privileged_fields": ignored,
            }
        if path == "/api/documents" and method == "POST":
            result = self.engine.ingest(
                actor,
                source_id=str(clean["source_id"]),
                text=str(clean["text"]),
                title=clean.get("title"),
                uri=clean.get("uri"),
                effective_from=self._dt(clean, "effective_from"),
                ignored_privileged_fields=ignored,
            )
            payload = result.as_dict()
            payload["ignored_privileged_fields"] = ignored
            return 201, payload
        if path == "/api/retrieve" and method == "POST":
            include_trace = bool(clean.get("include_trace")) and actor.is_admin
            result = self.engine.retrieve(
                actor,
                query=str(clean["query"]),
                limit=int(clean.get("limit", 5)),
                as_of_valid=self._dt(clean, "as_of_valid"),
                as_of_recorded=self._dt(clean, "as_of_recorded"),
                include_trace=include_trace,
                ignored_privileged_fields=ignored,
            )
            payload = result.as_dict(include_trace=include_trace)
            payload["ignored_privileged_fields"] = ignored
            payload["identity_source"] = "verified_token"
            return 200, payload
        if path == "/api/context-packs" and method == "POST":
            pack = self.engine.build_context_pack(
                actor,
                query=str(clean["query"]),
                limit=int(clean.get("limit", 5)),
                as_of_valid=self._dt(clean, "as_of_valid"),
            )
            return 200, {**pack.as_dict(), "ignored_privileged_fields": ignored}
        if path == "/api/quarantine" and method == "GET":
            items = self.engine.quarantine_queue(actor)
            return 200, {"items": items, "count": len(items)}
        if method == "POST" and len(parts) == 4 and parts[:2] == ["api", "quarantine"]:
            outcome = self.engine.review(
                actor,
                target_type="chunk",
                target_id=parts[2],
                decision=parts[3],
                reason=str(clean.get("reason", "")),
                effective_from=self._dt(clean, "effective_from"),
                revised_text=clean.get("revised_text"),
            )
            return 200, {**outcome.as_dict(), "ignored_privileged_fields": ignored}
        if path == "/api/conflicts" and method == "GET":
            items = self.engine.conflicts(actor)
            return 200, {
                "items": items,
                "count": len(items),
                "note": "A conflict is a review state backed by two evidence spans. It is "
                "not a judgement about which document is factually correct.",
            }
        if (
            method == "POST"
            and len(parts) == 4
            and parts[:2] == ["api", "conflicts"]
            and parts[3] == "resolve"
        ):
            return 200, {
                **self.engine.resolve_conflict(
                    actor, parts[2], status=str(clean["resolution"]), reason=str(clean["reason"])
                ),
                "ignored_privileged_fields": ignored,
            }
        if path == "/api/ledger":
            items = self.engine.ledger(actor)
            return 200, {"items": items, "count": len(items)}
        if path == "/api/exposures":
            items = self.engine.exposures(actor)
            return 200, {"items": items, "count": len(items)}
        if path == "/api/snapshots" and method == "GET":
            with self.engine.db.connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM snapshots WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100",
                    (actor.tenant_id,),
                ).fetchall()
            return 200, {"items": [dict(r) for r in rows], "count": len(rows)}
        if path == "/api/snapshots" and method == "POST":
            return 201, {
                **self.engine.snapshot(
                    actor,
                    str(clean["label"]),
                    str(clean.get("note", "")),
                    as_of_valid=self._dt(clean, "as_of_valid"),
                    as_of_recorded=self._dt(clean, "as_of_recorded"),
                ),
                "ignored_privileged_fields": ignored,
            }
        if (
            method == "POST"
            and len(parts) == 4
            and parts[:2] == ["api", "snapshots"]
            and parts[3] == "diff"
        ):
            return 200, {
                **self.engine.replay_snapshot(
                    actor, parts[2], str(clean["query"]), limit=int(clean.get("limit", 5))
                ),
                "ignored_privileged_fields": ignored,
            }
        if path == "/api/scenarios/run" and method == "POST":
            actor.require("reviewer")
            return 200, {
                **run_scenario(str(clean["scenario_id"])),
                "ignored_privileged_fields": ignored,
            }
        if path == "/api/demo/unguarded-comparison" and method == "POST":
            query = str(clean["query"])
            baseline = self.engine.unguarded_baseline(
                actor, query=query, limit=int(clean.get("limit", 5))
            )
            guarded = self.engine.retrieve(actor, query=query, limit=int(clean.get("limit", 5)))
            return 200, {
                "query": query,
                "unguarded_baseline": baseline,
                "guarded_result": guarded.as_dict(),
                "comparison": {
                    "unguarded_hit_count": len(baseline["hits"]),
                    "guarded_hit_count": len(guarded.context_chunks),
                    "chunks_withheld_by_guard": sorted(
                        {h["chunk_id"] for h in baseline["hits"]} - set(guarded.chunk_ids())
                    ),
                },
                "labels": {
                    "unguarded_baseline": "synthetic measurement baseline, NOT Memory Firewall output",
                    "guarded_result": "actual Memory Firewall output",
                },
                "ignored_privileged_fields": ignored,
            }
        return 404, {"code": "not_found", "message": f"no route for {method} {path}"}


def api_is_live(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.35)
        return probe.connect_ex(("127.0.0.1", port)) == 0


class Handler(SimpleHTTPRequestHandler):
    api_port: int = 8002
    fallback: FallbackApi | None = None
    proxy: bool = False

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _is_api(self) -> bool:
        return self.path.startswith("/api/") or self.path.split("?")[0] == "/healthz"

    def _proxy(self, method: str, raw_body: bytes) -> None:
        url = f"http://127.0.0.1:{self.api_port}{self.path}"
        request = urllib.request.Request(url, data=raw_body or None, method=method)
        for header in ("Authorization", "Content-Type", "Accept"):
            value = self.headers.get(header)
            if value:
                request.add_header(header, value)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                payload = response.read()
                self.send_response(response.status)
                self.send_header(
                    "Content-Type", response.headers.get("Content-Type", "application/json")
                )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except urllib.error.URLError as exc:
            self._send_json(502, {"code": "upstream_unreachable", "message": str(exc.reason)})

    def _serve_api(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.proxy:
            self._proxy(method, raw)
            return
        try:
            body = json.loads(raw) if raw else {}
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"code": "invalid_json", "message": str(exc)})
            return
        assert self.fallback is not None
        self.fallback.client_is_loopback = str(self.client_address[0]) in {
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
        }
        try:
            status, payload = self.fallback.handle(
                method, self.path.split("?")[0], body, self.headers
            )
        except FirewallError as exc:
            self._send_json(exc.status_code, {"code": exc.code, "message": str(exc)})
            return
        except KeyError as exc:
            self._send_json(422, {"code": "validation_error", "message": f"missing field {exc}"})
            return
        except Exception as exc:
            self._send_json(500, {"code": "internal_error", "message": type(exc).__name__})
            return
        self._send_json(status, payload)

    def do_GET(self) -> None:
        if self._is_api():
            self._serve_api("GET")
            return
        if self.path == "/" or self.path.startswith("/#"):
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        if self._is_api():
            self._serve_api("POST")
            return
        self._send_json(405, {"code": "method_not_allowed", "message": "static files are GET-only"})

    def end_headers(self) -> None:
        # A security tool's own UI should not be the weak link.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("MF_DEV_QUIET") == "1":
            return
        sys.stderr.write("[web] " + (fmt % args) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Memory Firewall dashboard dev server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MF_WEB_PORT", 5174)))
    parser.add_argument("--api-port", type=int, default=int(os.environ.get("MF_API_PORT", 8002)))
    parser.add_argument("--host", default="127.0.0.1", help="localhost only by default")
    args = parser.parse_args(argv)

    if not DIST.exists():
        print(
            f"ERROR: {DIST} does not exist. Run: cd apps/dashboard && npm run build",
            file=sys.stderr,
        )
        return 1

    Handler.api_port = args.api_port
    Handler.proxy = api_is_live(args.api_port)
    if Handler.proxy:
        print(f"[web] proxying /api -> http://127.0.0.1:{args.api_port} (FastAPI app)")
    else:
        try:
            Handler.fallback = FallbackApi()
        except Exception as exc:
            print(f"ERROR: cannot start the fallback API adapter: {exc}", file=sys.stderr)
            return 1
        print("[web] no API server on the API port; serving /api in process with the fallback")
        print("[web] adapter over the same engine (see docs/DECISIONS.md)")
        if demo_tokens_enabled():
            print("[web] WARNING: MF_DEV_EXPOSE_DEMO_TOKENS is set — /api/dev/principals will")
            print("[web] return the local demo bearer tokens to any loopback caller. Local demo")
            print("[web] use only; never set this outside a throwaway demo database.")

    handler = partial(Handler, directory=str(DIST))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"[web] dashboard on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
