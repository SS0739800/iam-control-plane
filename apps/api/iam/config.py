"""Application settings, loaded from the environment.

Every value has a working local default so a fresh clone runs without a .env,
but nothing secret has a usable default — SESSION_SECRET is deliberately an
obvious placeholder so it fails review rather than shipping quietly.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

PoolerMode = Literal["direct", "session", "transaction"]
AppEnv = Literal["local", "ci", "production"]

# Intentionally a hardcoded non-secret. `uses_placeholder_secret` compares
# against it so production refuses to start while it is still in place — the
# value existing in source is the mechanism, not an oversight.
PLACEHOLDER_SECRET = "dev-only-not-a-real-secret-change-me"  # noqa: S105


class Settings(BaseSettings):
    """Runtime configuration. Instantiate via :func:`get_settings`."""

    model_config = SettingsConfigDict(
        # Looked up relative to the process CWD: apps/api when running natively,
        # /srv in the container. The repo-root .env covers the compose case.
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------- application
    app_env: AppEnv = "local"
    log_level: str = "INFO"

    # Stamped by CI at image build time; surfaced on /api/health so you can
    # always tell what is actually deployed.
    git_sha: str = "dev"

    # The single origin everything is served from. In P2 this becomes the base
    # for the SAML entity ID and ACS URL, so it has to be right.
    base_url: str = "http://localhost:8080"

    # ------------------------------------------------------------- sessions
    session_secret: str = PLACEHOLDER_SECRET
    session_cookie_name: str = "iam_session"

    # ------------------------------------------------------------- database
    database_url: str = "postgresql+asyncpg://iam:iam@localhost:5432/iam"

    # Alembic needs a different connection path than the app on Supabase:
    # DDL and transaction-mode pooling do not mix. Falls back to database_url
    # locally, where both are the same server.
    alembic_database_url: str | None = None

    db_pooler_mode: PoolerMode = "direct"
    db_echo: bool = False

    # ---------------------------------------------------------- properties
    @property
    def migration_url(self) -> str:
        """Connection URL Alembic should use."""
        return self.alembic_database_url or self.database_url

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def uses_placeholder_secret(self) -> bool:
        return self.session_secret == PLACEHOLDER_SECRET


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton.

    FastAPI dependencies use this directly; tests clear the cache via the
    ``settings`` fixture rather than mutating the instance.
    """
    return Settings()
