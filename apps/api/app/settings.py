"""API settings.

Everything is environment-driven with safe defaults: localhost binding, the guard on, the labelled
unguarded baseline off, and no model key anywhere. ``.env.example`` documents every variable with a
placeholder value; the real ``.env`` is written by ``make setup`` and is gitignored.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MF_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    api_host: str = Field(default="127.0.0.1", description="Dev binding; localhost only.")
    api_port: int = Field(default=8002)
    web_port: int = Field(default=5174)
    db_path: Path = Field(default=Path("data/memory-firewall.sqlite3"))

    #: Comma-separated browser origins allowed to call the API. Defaults to the dev dashboard only.
    cors_origins: str = Field(default="http://127.0.0.1:5174,http://localhost:5174")

    max_document_bytes: int = Field(default=256 * 1024)
    max_upload_bytes: int = Field(default=256 * 1024)
    max_retrieve_limit: int = Field(default=25)
    min_retrieval_trust_tier: str = Field(default="external_untrusted")

    enable_unguarded_baseline: bool = Field(
        default=False,
        description=(
            "Exposes POST /api/demo/unguarded-comparison for measurement. Admin role is still "
            "required and every response is labelled as a baseline, not a firewall result."
        ),
    )
    strict_reject_forged_fields: bool = Field(
        default=False,
        description=(
            "When false (default) forged identity/privilege fields are ignored and audited; when "
            "true the request is rejected with 400. Both behaviours are tested."
        ),
    )
    hmac_key: str | None = Field(default=None, description="Optional manifest HMAC key.")
    llm_adapter: str = Field(default="null")

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    """Used by tests that need a different environment."""
    global _settings
    _settings = None
