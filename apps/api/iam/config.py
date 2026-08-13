"""Settings, read from environment variables.

Everything has a default that works locally, so a fresh clone runs without a .env
file. Nothing secret has a usable default though. SESSION_SECRET is an obvious
placeholder so it stands out in review instead of slipping through.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

PoolerMode = Literal["direct", "session", "transaction"]
AppEnv = Literal["local", "ci", "production"]

# Not a real secret, and it's in the source on purpose. uses_placeholder_secret
# compares against it so production refuses to boot while it's still here.
PLACEHOLDER_SECRET = "dev-only-not-a-real-secret-change-me"  # noqa: S105


class Settings(BaseSettings):
    """The app's settings. Get them with get_settings()."""

    model_config = SettingsConfigDict(
        # Found relative to wherever the process started: apps/api when run
        # directly, /srv in the container. The second path covers docker compose,
        # which reads the .env at the repo root.
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------- application
    app_env: AppEnv = "local"
    log_level: str = "INFO"

    # Set by CI when it builds the image, and shown on /api/health so you can
    # always tell what's actually running.
    git_sha: str = "dev"

    # The one address everything is served from. P2 builds the SAML URLs out of
    # this, so it has to be right.
    base_url: str = "http://localhost:8080"

    # ------------------------------------------------------------- sessions
    session_secret: str = PLACEHOLDER_SECRET
    session_cookie_name: str = "iam_session"

    # Stand-in for logging in, until P2 adds SAML. Who we assume is calling when
    # there's no X-Dev-Actor header. Never used in production, see
    # iam/security/actor.py.
    dev_actor_user_name: str | None = "admin@demo.local"

    # ------------------------------------------------------------- database
    database_url: str = "postgresql+asyncpg://iam:iam@localhost:5432/iam"

    # On Supabase, migrations have to connect a different way than the app does,
    # because schema changes and transaction-mode pooling don't mix. Locally both
    # point at the same server, so this falls back to database_url.
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
