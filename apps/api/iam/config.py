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

    # ------------------------------------------------- signing logins we issue
    # The keypair we sign assertions with, as PEM. Deliberately not in the
    # database: this key can mint a login for anybody, so it must not be in
    # something a dump or a backup carries around. See iam/saml/keys.py.
    #
    # No default. Production refuses to start without one; outside production a
    # throwaway pair is generated in memory and warned about loudly.
    saml_idp_private_key: str | None = None
    saml_idp_certificate: str | None = None

    # ------------------------------------------------- outbound provisioning
    scim_encryption_key: str | None = None
    """Encrypts the bearer tokens we send to downstream systems.

    A Fernet key. Left unset, one is derived from SESSION_SECRET, which is fine on a
    laptop and means rotating the session secret makes stored tokens unreadable. Set
    it explicitly anywhere that matters so the two rotate independently. Generate one
    with:

        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    See iam/secrets.py for why these are encrypted rather than hashed or kept in the
    environment like the signing key."""

    allow_private_provisioning_targets: bool = False
    """Allow a downstream on a private or loopback address in production.

    Off by default and deliberately long to type. Locally it is ignored — a target at
    http://hrms:8000 is the point of compose. Link-local is refused whatever this
    says, because that is where cloud metadata services live. See ADR 0007."""

    # ---------------------------------------------------------------- email
    # Mailpit in compose, which accepts anything and delivers nowhere. That is the
    # right default for a system that emails people about access: a misconfigured
    # environment should fail to reach anybody rather than mail a real person.
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = False
    mail_from: str = "iam@demo.local"

    mail_enabled: bool = True
    """Set false to log what would have been sent instead of sending it.

    Not a testing convenience — it is what keeps the notification optional. An
    approval must not fail because a mail server is down, so sending is best
    effort either way, and this makes "no mail server at all" a supported setup
    rather than a stream of errors."""

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

    # Development stand-in, used only when a request arrives with no session
    # cookie. Who we assume is calling when there's no X-Dev-Actor header either.
    # Set it to None to switch the stand-in off entirely; it never runs in
    # production regardless. See iam/security/actor.py.
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
