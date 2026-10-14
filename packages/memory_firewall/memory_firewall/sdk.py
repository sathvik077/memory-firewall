"""Python SDK.

The quickstart in ``CLAUDE.md`` §4B is implemented literally::

    from memory_firewall import MemoryFirewall

    firewall = MemoryFirewall.local("./data/memory-firewall.sqlite3")
    doc = firewall.ingest(source="demo-policy", text="Refunds allowed within 30 days",
                          tenant_id="demo")
    results = firewall.retrieve(query="What is the refund policy?", tenant_id="demo",
                                principal="demo-user")

**Why passing ``principal`` here is not a trust bypass.** The SDK runs in-process with direct
filesystem access to the database, so its caller is already the local operator — it is the
equivalent of a DBA shell, not of an HTTP client. What the ``principal`` argument does is *adopt*
an existing principal row and then obey that principal's ACL: the name is looked up in the
``principals`` table, and retrieval runs through the same guarded SQL with that principal's grants.
An unknown principal raises instead of defaulting to something permissive, and the SDK cannot set a
trust tier from document text any more than the API can. Over HTTP, identity still comes only from
a bearer token — ``tests/security/test_forged_identity.py`` covers both paths.

Convenience behaviour, documented because it is surprising otherwise: ``ingest`` will create a
missing tenant and a missing source so the quickstart works on an empty database, and an
auto-created source gets trust tier ``unreviewed_internal``. Promotion to an authoritative tier is
always an explicit administrative call.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import FirewallConfig
from .contextpack import ContextPack
from .engine import IngestResult, MemoryFirewallEngine, ReviewOutcome
from .errors import NotFoundError
from .identity import Principal
from .retrieval import RetrievalResult

__all__ = ["MemoryFirewall"]

DEFAULT_TENANT = "demo"
LOCAL_ADMIN = "local-admin"
AUTO_SOURCE_TRUST_TIER = "unreviewed_internal"


class MemoryFirewall:
    """Local, embedded entry point to the firewall."""

    def __init__(self, engine: MemoryFirewallEngine) -> None:
        self.engine = engine
        self._admin = Principal(id=LOCAL_ADMIN, tenant_id=DEFAULT_TENANT, role="admin")

    # ------------------------------------------------------------------ construction ----------
    @classmethod
    def local(
        cls,
        db_path: str | Path = "data/memory-firewall.sqlite3",
        *,
        config: FirewallConfig | None = None,
        tenant_id: str = DEFAULT_TENANT,
    ) -> MemoryFirewall:
        """Open (or create) a local database and ensure a local admin principal exists."""
        engine = MemoryFirewallEngine(db_path, config=config)
        firewall = cls(engine)
        firewall._admin = Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        firewall._ensure_tenant(tenant_id)
        firewall._ensure_principal(LOCAL_ADMIN, tenant_id, "admin")
        return firewall

    # ------------------------------------------------------------------ helpers ---------------
    def _ensure_tenant(self, tenant_id: str) -> None:
        with self.engine.db.connect() as conn:
            if conn.execute("SELECT 1 FROM tenants WHERE id=?", (tenant_id,)).fetchone():
                return
        bootstrap = Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        self.engine.create_tenant(bootstrap, tenant_id, tenant_id)

    def _ensure_principal(self, principal_id: str, tenant_id: str, role: str) -> Principal:
        with self.engine.db.connect() as conn:
            row = conn.execute(
                "SELECT id, tenant_id, role FROM principals WHERE id=?", (principal_id,)
            ).fetchone()
        if row:
            return Principal(id=row["id"], tenant_id=row["tenant_id"], role=row["role"])
        admin = Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        principal, _token = self.engine.create_principal(admin, principal_id, tenant_id, role)
        return principal

    def _principal(self, principal_id: str | None, tenant_id: str) -> Principal:
        if principal_id is None:
            return Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        with self.engine.db.connect() as conn:
            row = conn.execute(
                "SELECT id, tenant_id, role, status FROM principals WHERE id=?", (principal_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(
                f"unknown principal '{principal_id}'. Create it with create_principal() first; the "
                "SDK does not invent identities at retrieval time."
            )
        if row["tenant_id"] != tenant_id:
            raise NotFoundError(f"unknown principal '{principal_id}'")
        return Principal(id=row["id"], tenant_id=row["tenant_id"], role=row["role"])

    # ------------------------------------------------------------------ administration --------
    def create_tenant(self, tenant_id: str, name: str = "") -> dict[str, Any]:
        self._ensure_tenant(tenant_id)
        return {"tenant_id": tenant_id, "name": name or tenant_id}

    def create_principal(
        self,
        principal_id: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
        role: str = "reader",
        token: str | None = None,
    ) -> tuple[Principal, str]:
        self._ensure_tenant(tenant_id)
        admin = Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        return self.engine.create_principal(admin, principal_id, tenant_id, role, token)

    def create_source(
        self,
        source_id: str,
        *,
        trust_tier: str,
        read_acl: Sequence[str] = (),
        tenant_id: str = DEFAULT_TENANT,
        connector_type: str = "manual",
    ) -> dict[str, Any]:
        self._ensure_tenant(tenant_id)
        admin = Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        return self.engine.create_source(
            admin,
            source_id,
            trust_tier=trust_tier,
            read_acl=read_acl,
            tenant_id=tenant_id,
            connector_type=connector_type,
        )

    # ------------------------------------------------------------------ core ------------------
    def ingest(
        self,
        *,
        source: str,
        text: str,
        tenant_id: str = DEFAULT_TENANT,
        title: str | None = None,
        uri: str | None = None,
        document_id: str | None = None,
        effective_from: datetime | None = None,
        actor: str | None = None,
    ) -> IngestResult:
        """Ingest content through the full pre-write pipeline."""
        self._ensure_tenant(tenant_id)
        self._ensure_principal(LOCAL_ADMIN, tenant_id, "admin")
        with self.engine.db.connect() as conn:
            exists = conn.execute("SELECT 1 FROM sources WHERE id=?", (source,)).fetchone()
        if not exists:
            self.create_source(
                source,
                trust_tier=AUTO_SOURCE_TRUST_TIER,
                read_acl=[LOCAL_ADMIN],
                tenant_id=tenant_id,
            )
        principal = (
            self._principal(actor, tenant_id)
            if actor
            else Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        )
        return self.engine.ingest(
            principal,
            source_id=source,
            text=text,
            title=title,
            uri=uri,
            document_id=document_id,
            effective_from=effective_from,
        )

    def retrieve(
        self,
        *,
        query: str,
        tenant_id: str = DEFAULT_TENANT,
        principal: str | None = None,
        limit: int = 5,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
        include_trace: bool = False,
    ) -> RetrievalResult:
        """Retrieve through the full pre-retrieval guard as ``principal``."""
        actor = self._principal(principal, tenant_id)
        return self.engine.retrieve(
            actor,
            query=query,
            limit=limit,
            as_of_valid=as_of_valid,
            as_of_recorded=as_of_recorded,
            include_trace=include_trace,
        )

    def context_pack(
        self,
        *,
        query: str,
        tenant_id: str = DEFAULT_TENANT,
        principal: str | None = None,
        limit: int = 5,
        as_of_valid: datetime | None = None,
    ) -> ContextPack:
        actor = self._principal(principal, tenant_id)
        return self.engine.build_context_pack(
            actor, query=query, limit=limit, as_of_valid=as_of_valid
        )

    def review(
        self,
        *,
        target_type: str,
        target_id: str,
        decision: str,
        reason: str,
        tenant_id: str = DEFAULT_TENANT,
        reviewer: str | None = None,
        effective_from: datetime | None = None,
        revised_text: str | None = None,
    ) -> ReviewOutcome:
        actor = (
            self._principal(reviewer, tenant_id)
            if reviewer
            else Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        )
        return self.engine.review(
            actor,
            target_type=target_type,
            target_id=target_id,
            decision=decision,
            reason=reason,
            effective_from=effective_from,
            revised_text=revised_text,
        )

    def quarantine(
        self, *, tenant_id: str = DEFAULT_TENANT, reviewer: str | None = None
    ) -> list[dict[str, Any]]:
        actor = (
            self._principal(reviewer, tenant_id)
            if reviewer
            else Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin")
        )
        return self.engine.quarantine_queue(actor)

    def stats(self, *, tenant_id: str = DEFAULT_TENANT) -> dict[str, Any]:
        return self.engine.stats(Principal(id=LOCAL_ADMIN, tenant_id=tenant_id, role="admin"))

    def load_directory(
        self,
        path: str | Path,
        *,
        source: str,
        tenant_id: str = DEFAULT_TENANT,
        suffixes: Sequence[str] = (".md", ".txt"),
        max_files: int = 500,
    ) -> list[IngestResult]:
        """Import a local directory of text/markdown files. See ``adapters.directory``."""
        from .adapters.directory import DirectoryAdapter

        adapter = DirectoryAdapter(path, suffixes=tuple(suffixes), max_files=max_files)
        results: list[IngestResult] = []
        for item in adapter.iter_documents():
            results.append(
                self.ingest(
                    source=source,
                    text=item.text,
                    tenant_id=tenant_id,
                    title=item.title,
                    uri=item.relative_path,
                )
            )
        return results
