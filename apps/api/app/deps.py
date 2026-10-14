"""Shared dependencies: the engine instance, authentication and body hygiene."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request

from memory_firewall.config import FirewallConfig
from memory_firewall.engine import MemoryFirewallEngine
from memory_firewall.errors import AuthenticationError, FirewallError
from memory_firewall.identity import Principal, strip_forgeable_fields

from .settings import Settings, get_settings

_engine: MemoryFirewallEngine | None = None


def build_engine(settings: Settings | None = None) -> MemoryFirewallEngine:
    settings = settings or get_settings()
    config = FirewallConfig(
        db_path=settings.db_path,
        min_retrieval_trust_tier=settings.min_retrieval_trust_tier,
        max_document_bytes=settings.max_document_bytes,
        max_retrieve_limit=settings.max_retrieve_limit,
        hmac_key=settings.hmac_key.encode("utf-8") if settings.hmac_key else None,
        enable_unguarded_baseline=settings.enable_unguarded_baseline,
        strict_reject_forged_fields=settings.strict_reject_forged_fields,
    )
    return MemoryFirewallEngine(settings.db_path, config=config)


def get_engine() -> MemoryFirewallEngine:
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def set_engine(engine: MemoryFirewallEngine | None) -> None:
    """Test hook. Not reachable from any route."""
    global _engine
    _engine = engine


def current_principal(
    authorization: Annotated[str | None, Header()] = None,
    engine: MemoryFirewallEngine = Depends(get_engine),
) -> Principal:
    """Resolve the caller from the bearer token and nothing else.

    There is no header, query parameter or body field that can substitute for this. A missing or
    malformed ``Authorization`` header is a 401 with a message that does not reveal whether a given
    token exists.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "authentication_required",
                "message": "send 'Authorization: Bearer <token>'. Tokens are issued by make setup.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        return engine.authenticate(token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": "authentication_required", "message": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def clean_json_body(request: Request) -> tuple[dict[str, Any], list[str]]:
    """Read, bound and sanitise a JSON body.

    Returns ``(clean_payload, ignored_privileged_fields)``. Identity and privilege fields are
    removed *before* validation so that no handler can read them even by accident, and the list of
    what was removed is carried forward so it can be audited and echoed back to the caller.
    """
    settings = get_settings()
    if request.headers.get("content-type", "").split(";")[0].strip() not in {
        "application/json",
        "",
    }:
        raise HTTPException(
            status_code=415,
            detail={"code": "unsupported_media_type", "message": "send application/json"},
        )
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_document_bytes * 2:
        raise HTTPException(
            status_code=413,
            detail={"code": "payload_too_large", "message": "request body is too large"},
        )
    raw = await request.body()
    if len(raw) > settings.max_document_bytes * 2:
        raise HTTPException(
            status_code=413,
            detail={"code": "payload_too_large", "message": "request body is too large"},
        )
    if not raw:
        return {}, []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400, detail={"code": "invalid_json", "message": "body is not valid JSON"}
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_json", "message": "body must be a JSON object"},
        )
    clean, ignored = strip_forgeable_fields(payload)
    if ignored and settings.strict_reject_forged_fields:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "privileged_field_rejected",
                "message": (
                    "identity and privilege fields cannot be supplied by the caller; they are "
                    "resolved from the bearer token and from protected server state"
                ),
                "fields": ignored,
            },
        )
    return clean, ignored


def to_http(exc: FirewallError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}
    )
