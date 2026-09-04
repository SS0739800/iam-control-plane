"""Settings, read from environment variables.

Everything has a default that works locally, so a fresh clone runs without a .env
file. Nothing secret has a usable default though. SESSION_SECRET defaults to an
obvious placeholder so it stands out in review instead of slipping through.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

PoolerMode = Literal["direct", "session", "transaction"]
AppEnv = Literal["local", "ci", "production"]

# Not a real secret. uses_placeholder_secret compares against it so production
# refuses to boot while it's still set.
PLACEHOLDER_SECRET = "dev-only-not-a-real-secret-change-me"  # noqa: S105


# Query parameters that libpq understands and asyncpg does not. SQLAlchemy passes
# query parameters straight to the driver, so an unrecognized one reaches
# asyncpg.connect() as a keyword argument it doesn't accept, which raises
# TypeError on the first query. Renamed where asyncpg has an equivalent, dropped
# where it has none.
ASYNCPG_RENAMES = {"sslmode": "ssl"}
ASYNCPG_UNSUPPORTED = ("channel_binding",)


def for_asyncpg(url: str) -> str:
    """Make a connection URL from a provider's dashboard usable by asyncpg.

    Managed Postgres providers hand out libpq-style URLs. Two query parameters in
    those break asyncpg: ``sslmode`` is just a naming difference, so it's renamed to
    ``ssl`` (same values, e.g. "require", "verify-full"). ``channel_binding`` has no
    asyncpg equivalent and is dropped — asyncpg still connects with ``ssl=require``
    encrypted, just without SCRAM channel binding.

    Note: the readiness endpoint hides exception messages since they can contain the
    connection string, so a bad parameter here surfaces in production only as
    ``{"detail": "TypeError"}``.

    Anything else in the query string is left alone; an unsupported parameter that
    isn't listed above will still fail asyncpg.connect().
    """
    scheme, separator, query = url.partition("?")
    if not separator:
        return url

    kept: list[str] = []
    for parameter in query.split("&"):
        key, has_value, value = parameter.partition("=")
        if key in ASYNCPG_UNSUPPORTED:
            continue
        if key in ASYNCPG_RENAMES:
            key = ASYNCPG_RENAMES[key]
        kept.append(f"{key}={value}" if has_value else key)

    return f"{scheme}?{'&'.join(kept)}" if kept else scheme


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
    # The keypair we sign assertions with, as PEM. Not stored in the database:
    # this key can mint a login for anybody, so it shouldn't end up in a dump or
    # backup. See iam/saml/keys.py.
    #
    # No default. Production refuses to start without one; outside production a
    # throwaway pair is generated in memory and a warning is logged.
    saml_idp_private_key: str | None = None
    saml_idp_certificate: str | None = None

    # ------------------------------------------------- outbound provisioning
    scim_encryption_key: str | None = None
    """Encrypts the bearer tokens we send to downstream systems.

    A Fernet key. If unset, one is derived from SESSION_SECRET — fine on a laptop,
    but rotating the session secret then makes stored tokens unreadable. Set this
    explicitly anywhere that matters so the two rotate independently. Generate one
    with:

        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    See iam/secrets.py for why these are encrypted rather than hashed."""

    allow_private_provisioning_targets: bool = False
    """Allow a downstream on a private or loopback address in production.

    Off by default. Ignored locally, since a target at http://hrms:8000 is normal
    for compose. Link-local addresses are refused regardless, since that's where
    cloud metadata services live. See ADR 0007."""

    # ---------------------------------------------------------------- email
    # Mailpit in compose: accepts anything and delivers nowhere. Good default for
    # a system that emails people about access — a misconfigured environment
    # should fail to reach anybody rather than mail a real person.
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = False
    mail_from: str = "iam@demo.local"

    mail_enabled: bool = True
    """Set false to log what would have been sent instead of sending it.

    Sending is always best effort — an approval must not fail just because a mail
    server is down. This flag makes "no mail server at all" a supported setup
    instead of a stream of errors."""

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

    # Development stand-in used when a request has no session cookie and no
    # X-Dev-Actor header. Set to None to disable it; it never runs in production
    # regardless. See iam/security/actor.py.
    dev_actor_user_name: str | None = "admin@demo.local"

    # ------------------------------------------------------------- database
    database_url: str = "postgresql+asyncpg://iam:iam@localhost:5432/iam"

    # Migrations need a different connection than the app on hosted Postgres,
    # since schema changes don't work through transaction-mode pooling. Locally
    # both point at the same server, so this falls back to database_url.
    alembic_database_url: str | None = None

    db_pooler_mode: PoolerMode = "direct"
    db_echo: bool = False

    # ------------------------------------------------------- the built frontend
    # Where the compiled SPA lives, for production where this process serves it
    # alongside the API. Unset means no mount, which is what local dev and tests
    # use — Caddy proxies the Vite dev server instead. See
    # docs/adr/0008-one-image-in-production.md.
    static_dir: str | None = None

    # ------------------------------------------------------- the background sweep
    # How often the worker reconciles every enabled provisioning target. Only the
    # worker process reads this; the web process ignores it.
    #
    # Five minutes trades off leaver accounts closing promptly against not
    # hammering a downstream with pointless passes when nothing changed.
    provisioning_sweep_seconds: int = 300

    # ---------------------------------------------------------- properties
    @property
    def app_url(self) -> str:
        """Connection URL the app should use, in a form asyncpg accepts."""
        return for_asyncpg(self.database_url)

    @property
    def migration_url(self) -> str:
        """Connection URL Alembic should use, in a form asyncpg accepts."""
        return for_asyncpg(self.alembic_database_url or self.database_url)

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
