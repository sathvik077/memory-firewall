"""FastAPI application.

The HTTP layer is deliberately thin: it authenticates, bounds and sanitises input, calls
``MemoryFirewallEngine``, and serialises the result. Every security decision lives in the engine, so
the API and the SDK cannot diverge and a test that proves a property through one path proves it for
the other.

Conventions that are part of the security contract, not style choices:

* Identity comes only from ``Authorization: Bearer <token>``. Identity and privilege fields are
  stripped from every request body before validation, recorded as an audit event and echoed back in
  ``ignored_privileged_fields`` so a caller can see that their attempt was ignored.
* Mutating routes require ``reviewer``; administrative routes require ``admin``.
* Cross-tenant and nonexistent targets both answer 404 with the same body, so status codes cannot
  be used as an existence oracle for another tenant's data.
* The default binding is ``127.0.0.1`` and CORS allows only the dev dashboard origin.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from memory_firewall._version import DETECTOR_VERSION, POLICY_REVISION, __version__
from memory_firewall.adapters.llm import get_adapter
from memory_firewall.engine import MemoryFirewallEngine
from memory_firewall.errors import FirewallError
from memory_firewall.identity import Principal
from memory_firewall.scenarios import SCENARIOS, run_scenario

from . import schemas
from .deps import clean_json_body, current_principal, get_engine
from .settings import get_settings

CleanBody = Annotated[tuple[dict[str, Any], list[str]], Depends(clean_json_body)]
Caller = Annotated[Principal, Depends(current_principal)]
Engine = Annotated[MemoryFirewallEngine, Depends(get_engine)]

DESCRIPTION = """
Memory Firewall wraps the **write**, **retrieve** and **use** points of an agent memory / RAG
pipeline.

* Trust tiers are administrative state. Nothing a document *says* about itself can change them.
* Identity, tenant and role come from the bearer token, never from a request body.
* The pre-retrieval guard is part of the SQL that performs the search, so an ineligible chunk cannot
  be ranked, counted, cited or returned — even if it was forced into the index.
* With no eligible evidence the API fails safe: an empty context pack and no answer.

**Bounded claims.** This detects a closed set of structural and lexical signals; it does not detect
all semantic poisoning. A digest proves consistency with a separately stored expected value, not
safety. Protection applies only to content that flows through this pipeline. See `docs/SECURITY.md`.
"""


def _validate[M: BaseModel](model: type[M], payload: dict[str, Any]) -> M:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": "invalid request body",
                "errors": exc.errors(include_url=False),
            },
        ) from exc


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Memory Firewall API",
        version=__version__,
        description=DESCRIPTION,
        license_info={"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
        openapi_tags=[
            {"name": "health", "description": "Liveness and build information."},
            {"name": "admin", "description": "Tenant, principal and source administration."},
            {"name": "ingest", "description": "Enforcement point 1: pre-write scanning."},
            {"name": "retrieve", "description": "Enforcement point 2: pre-retrieval guard."},
            {"name": "use", "description": "Enforcement point 3: context packs and answers."},
            {"name": "review", "description": "Reviewer workflow, conflicts and audit."},
            {"name": "forensics", "description": "Ledger, exposures, snapshots, time machine."},
            {"name": "demo", "description": "Attack lab and labelled measurement baseline."},
        ],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(FirewallError)
    async def firewall_error_handler(_: Request, exc: FirewallError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code, content={"code": exc.code, "message": str(exc)}
        )

    @app.exception_handler(sqlite3.Error)
    async def sqlite_error_handler(_: Request, exc: sqlite3.Error) -> JSONResponse:
        # Fail closed and say nothing about schema internals.
        return JSONResponse(
            status_code=503,
            content={
                "code": "storage_unavailable",
                "message": "the storage layer refused the operation; no memory was returned",
            },
        )

    # ---------------------------------------------------------------- health ------------------
    @app.get("/healthz", tags=["health"], response_model=schemas.HealthResponse)
    def healthz(engine: Engine) -> schemas.HealthResponse:
        notes: list[str] = []
        fts5 = True
        try:
            with engine.db.connect() as conn:
                conn.execute("SELECT 1 FROM fts_chunks LIMIT 1").fetchone()
        except sqlite3.Error:
            fts5 = False
            notes.append("FTS5 virtual table is unavailable; real retrieval is not possible")
        if settings.enable_unguarded_baseline:
            notes.append(
                "the labelled unguarded measurement baseline endpoint is ENABLED (admin only)"
            )
        return schemas.HealthResponse(
            status="ok" if fts5 else "degraded",
            schema_version=engine.db.schema_version(),
            detector_version=DETECTOR_VERSION,
            policy_revision=POLICY_REVISION,
            fts5=fts5,
            database=str(engine.config.db_path),
            unguarded_baseline_enabled=settings.enable_unguarded_baseline,
            notes=notes,
        )

    @app.get("/api/whoami", tags=["health"])
    def whoami(caller: Caller) -> dict[str, Any]:
        """Echo the identity the server resolved. Useful for showing that forgery had no effect."""
        return {**caller.as_dict(), "identity_source": "verified_token"}

    # ---------------------------------------------------------------- admin -------------------
    @app.get("/api/sources", tags=["admin"])
    def list_sources(caller: Caller, engine: Engine) -> dict[str, Any]:
        return {"sources": engine.sources(caller), "identity_source": "verified_token"}

    @app.post("/api/sources", tags=["admin"], status_code=201)
    def create_source(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.CreateSourceRequest, clean)
        data = engine.create_source(
            caller,
            req.source_id,
            trust_tier=req.trust_tier_assignment,
            read_acl=req.read_acl,
            connector_type=req.connector_type,
            owner=req.owner,
            expires_at=req.expires_at,
        )
        return {**data, "ignored_privileged_fields": ignored, "identity_source": "verified_token"}

    @app.post("/api/sources/{source_id}/acl", tags=["admin"])
    def set_acl(source_id: str, caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.SetAclRequest, clean)
        data = engine.set_source_acl(caller, source_id, req.read_acl)
        return {**data, "ignored_privileged_fields": ignored}

    @app.post("/api/sources/{source_id}/revoke", tags=["admin"])
    def revoke_source(
        source_id: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.RevokeSourceRequest, clean)
        data = engine.revoke_source(caller, source_id, req.reason)
        return {**data, "ignored_privileged_fields": ignored}

    # ---------------------------------------------------------------- ingest ------------------
    @app.post("/api/documents", tags=["ingest"], status_code=201)
    def ingest_document(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        """Enforcement point 1. The response reports the decision and the evidence for it."""
        clean, ignored = body
        req = _validate(schemas.IngestRequest, clean)
        result = engine.ingest(
            caller,
            source_id=req.source_id,
            text=req.text,
            title=req.title,
            uri=req.uri,
            effective_from=req.effective_from,
            ignored_privileged_fields=ignored,
        )
        payload = result.as_dict()
        payload["ignored_privileged_fields"] = ignored
        return payload

    @app.post("/api/documents/{document_id}/versions", tags=["ingest"], status_code=201)
    def ingest_revision(
        document_id: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.RevisionRequest, clean)
        result = engine.ingest(
            caller,
            source_id=req.source_id,
            text=req.text,
            title=req.title,
            document_id=document_id,
            effective_from=req.effective_from,
            ignored_privileged_fields=ignored,
        )
        payload = result.as_dict()
        payload["ignored_privileged_fields"] = ignored
        return payload

    @app.post("/api/documents/upload", tags=["ingest"], status_code=201)
    async def upload_document(
        caller: Caller,
        engine: Engine,
        file: UploadFile,
        source_id: Annotated[str, Query(min_length=1, max_length=120)],
        title: Annotated[str | None, Query(max_length=300)] = None,
    ) -> dict[str, Any]:
        """Bounded file upload: allow-listed suffixes, size cap, UTF-8 text only, no URL fetch."""
        name = (file.filename or "").strip()
        suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        if suffix not in engine.config.allowed_upload_suffixes:
            raise HTTPException(
                status_code=415,
                detail={
                    "code": "unsupported_media_type",
                    "message": f"only {', '.join(engine.config.allowed_upload_suffixes)} are accepted",
                },
            )
        raw = await file.read(settings.max_upload_bytes + 1)
        if len(raw) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail={"code": "payload_too_large", "message": "uploaded file is too large"},
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=415,
                detail={"code": "unsupported_media_type", "message": "file must be UTF-8 text"},
            ) from exc
        result = engine.ingest(
            caller, source_id=source_id, text=text, title=title or name, uri=f"upload://{name}"
        )
        return result.as_dict()

    @app.get("/api/documents/{document_id}/versions", tags=["ingest"])
    def document_versions(document_id: str, caller: Caller, engine: Engine) -> dict[str, Any]:
        return engine.document_versions(caller, document_id)

    # ---------------------------------------------------------------- retrieve ----------------
    @app.post("/api/retrieve", tags=["retrieve"])
    def retrieve(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        """Enforcement point 2. ``tenant_id`` / ``principal`` in the body are ignored by design."""
        clean, ignored = body
        req = _validate(schemas.RetrieveRequest, clean)
        result = engine.retrieve(
            caller,
            query=req.query,
            limit=req.limit,
            as_of_valid=req.as_of_valid,
            as_of_recorded=req.as_of_recorded,
            include_trace=req.include_trace and caller.is_admin,
            ignored_privileged_fields=ignored,
        )
        payload = result.as_dict(include_trace=req.include_trace and caller.is_admin)
        payload["ignored_privileged_fields"] = ignored
        payload["identity_source"] = "verified_token"
        return payload

    @app.post("/api/context-packs", tags=["use"])
    def context_pack(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        """Enforcement point 3. Only eligible chunks are in the pack; empty packs fail safe."""
        clean, ignored = body
        req = _validate(schemas.ContextPackRequest, clean)
        pack = engine.build_context_pack(
            caller,
            query=req.query,
            limit=req.limit,
            as_of_valid=req.as_of_valid,
            as_of_recorded=req.as_of_recorded,
            include_answer=req.include_answer,
        )
        payload = pack.as_dict()
        payload["ignored_privileged_fields"] = ignored
        return payload

    @app.post("/api/qa", tags=["use"])
    def qa(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        """Optional answer endpoint. Deterministic by default; no provider is required or called."""
        clean, ignored = body
        req = _validate(schemas.QaRequest, clean)
        pack = engine.build_context_pack(
            caller, query=req.question, limit=req.limit, as_of_valid=req.as_of_valid
        )
        adapter = get_adapter(settings.llm_adapter)
        response = adapter.complete(question=req.question, context_pack=pack.as_dict())
        return {
            "question": req.question,
            "answer": response.text,
            "declined": response.declined,
            "decline_reason": response.reason,
            "llm": response.as_dict(),
            "context_pack": pack.as_dict(),
            "ignored_privileged_fields": ignored,
            "identity_source": "verified_token",
        }

    # ---------------------------------------------------------------- review ------------------
    @app.get("/api/quarantine", tags=["review"])
    def quarantine(
        caller: Caller,
        engine: Engine,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        items = engine.quarantine_queue(caller, limit=limit, offset=offset)
        return {"items": items, "count": len(items), "limit": limit, "offset": offset}

    @app.post("/api/quarantine/{chunk_id}/{decision}", tags=["review"])
    def review_chunk(
        chunk_id: str, decision: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        clean, ignored = body
        payload = {**clean, "decision": decision}
        req = _validate(schemas.ReviewRequest, payload)
        outcome = engine.review(
            caller,
            target_type=req.target_type,
            target_id=chunk_id,
            decision=req.decision,
            reason=req.reason,
            effective_from=req.effective_from,
            revised_text=req.revised_text,
        )
        return {**outcome.as_dict(), "ignored_privileged_fields": ignored}

    @app.post("/api/versions/{version_id}/{decision}", tags=["review"])
    def review_version(
        version_id: str, decision: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        clean, ignored = body
        payload = {**clean, "decision": decision, "target_type": "version"}
        req = _validate(schemas.ReviewRequest, payload)
        outcome = engine.review(
            caller,
            target_type="version",
            target_id=version_id,
            decision=req.decision,
            reason=req.reason,
            effective_from=req.effective_from,
            revised_text=req.revised_text,
        )
        return {**outcome.as_dict(), "ignored_privileged_fields": ignored}

    @app.get("/api/conflicts", tags=["review"])
    def conflicts(
        caller: Caller, engine: Engine, status: Annotated[str | None, Query()] = None
    ) -> dict[str, Any]:
        items = engine.conflicts(caller, status=status)
        return {
            "items": items,
            "count": len(items),
            "note": (
                "A conflict is a review state backed by two evidence spans. It is not a judgement "
                "about which document is factually correct."
            ),
        }

    @app.post("/api/conflicts/{conflict_id}/resolve", tags=["review"])
    def resolve_conflict(
        conflict_id: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.ResolveConflictRequest, clean)
        data = engine.resolve_conflict(
            caller, conflict_id, status=req.resolution, reason=req.reason
        )
        return {**data, "ignored_privileged_fields": ignored}

    @app.get("/api/audit", tags=["review"])
    def audit_log(
        caller: Caller,
        engine: Engine,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        items = engine.audit_log(caller, limit=limit, offset=offset)
        return {"items": items, "count": len(items)}

    # ---------------------------------------------------------------- forensics ---------------
    @app.get("/api/ledger", tags=["forensics"])
    def ledger(
        caller: Caller, engine: Engine, limit: Annotated[int, Query(ge=1, le=500)] = 100
    ) -> dict[str, Any]:
        items = engine.ledger(caller, limit=limit)
        return {"items": items, "count": len(items)}

    @app.get("/api/stats", tags=["forensics"])
    def stats(caller: Caller, engine: Engine) -> dict[str, Any]:
        return engine.stats(caller)

    @app.get("/api/exposures", tags=["forensics"])
    def exposures(
        caller: Caller,
        engine: Engine,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        run_id: Annotated[str | None, Query()] = None,
    ) -> dict[str, Any]:
        items = engine.exposures(caller, limit=limit, run_id=run_id)
        return {"items": items, "count": len(items)}

    @app.get("/api/exposures/{run_id}", tags=["forensics"])
    def exposure(run_id: str, caller: Caller, engine: Engine) -> dict[str, Any]:
        items = engine.exposures(caller, limit=1, run_id=run_id)
        if not items:
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "exposure not found"}
            )
        return items[0]

    @app.post("/api/snapshots", tags=["forensics"], status_code=201)
    def create_snapshot(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        clean, ignored = body
        req = _validate(schemas.SnapshotRequest, clean)
        data = engine.snapshot(
            caller,
            req.label,
            req.note,
            as_of_valid=req.as_of_valid,
            as_of_recorded=req.as_of_recorded,
        )
        return {**data, "ignored_privileged_fields": ignored}

    @app.get("/api/snapshots", tags=["forensics"])
    def list_snapshots(caller: Caller, engine: Engine) -> dict[str, Any]:
        with engine.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM snapshots WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100",
                (caller.tenant_id,),
            ).fetchall()
        return {"items": [dict(r) for r in rows], "count": len(rows)}

    @app.post("/api/snapshots/{snapshot_id}/diff", tags=["forensics"])
    def snapshot_diff(
        snapshot_id: str, caller: Caller, engine: Engine, body: CleanBody
    ) -> dict[str, Any]:
        """Time machine: replay a query as of a snapshot's valid *and* recorded coordinates."""
        clean, ignored = body
        req = _validate(schemas.ReplayRequest, clean)
        data = engine.replay_snapshot(caller, snapshot_id, req.query, limit=req.limit)
        return {**data, "ignored_privileged_fields": ignored}

    # ---------------------------------------------------------------- demo --------------------
    @app.get("/api/dev/principals", tags=["demo"])
    def dev_principals() -> dict[str, Any]:
        """Localhost-only convenience so the demo dashboard can offer an 'Acting as' switcher.

        Returns the demo tokens that `make setup` generated, which grant access to the local demo
        database and nothing else. Disabled unless MF_DEV_EXPOSE_DEMO_TOKENS is truthy, and never
        enabled by the Docker image or any production profile.
        """
        import os

        # Defaults OFF, identically to the fallback adapter in scripts/serve_dashboard.py.
        # tests/integration/test_route_parity.py asserts the two agree, because an earlier
        # divergence here was a real unauthenticated credential disclosure.
        if os.environ.get("MF_DEV_EXPOSE_DEMO_TOKENS", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "not_found",
                    "message": (
                        "demo token listing is disabled. Set MF_DEV_EXPOSE_DEMO_TOKENS=1 for a "
                        "local demo, or paste a bearer token into the dashboard."
                    ),
                },
            )
        import sys as _sys
        from pathlib import Path as _Path

        _sys.path.insert(0, str(_Path(__file__).resolve().parents[3] / "scripts"))
        from serve_dashboard import demo_principals  # local dev helper

        return {"items": demo_principals()}

    @app.get("/api/scenarios", tags=["demo"])
    def list_scenarios() -> dict[str, Any]:
        return {
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
            "note": (
                "Each scenario runs against a fresh disposable database so results are repeatable "
                "and no scenario can contaminate another."
            ),
        }

    @app.post("/api/scenarios/run", tags=["demo"])
    def run_scenario_route(caller: Caller, body: CleanBody) -> dict[str, Any]:
        caller.require("reviewer")
        clean, ignored = body
        req = _validate(schemas.ScenarioRunRequest, clean)
        result = run_scenario(req.scenario_id)
        return {**result, "ignored_privileged_fields": ignored}

    @app.post("/api/demo/unguarded-comparison", tags=["demo"])
    def unguarded_comparison(caller: Caller, engine: Engine, body: CleanBody) -> dict[str, Any]:
        """Labelled measurement baseline. Admin + explicit env flag; never a firewall result."""
        clean, ignored = body
        req = _validate(schemas.UnguardedComparisonRequest, clean)
        baseline = engine.unguarded_baseline(caller, query=req.query, limit=req.limit)
        guarded = engine.retrieve(caller, query=req.query, limit=req.limit)
        return {
            "query": req.query,
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

    return app


app = create_app()
