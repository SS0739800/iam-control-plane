"""Builds the app.

create_app takes optional settings so a test can build its own copy. The `app` at
the bottom of the file is what uvicorn loads when it starts the server.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from iam import __version__
from iam.config import Settings, get_settings
from iam.db import build_engine, build_sessionmaker
from iam.logging_setup import configure_logging
from iam.routers import (
    applications,
    audit,
    dashboard,
    groups,
    health,
    identity_providers,
    login_inspector,
    me,
    saml,
    users,
)

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app.

    Args:
        settings: Use these instead of reading the environment. Tests pass their
            own; leave it None everywhere else.
    """
    resolved = settings if settings is not None else get_settings()
    configure_logging(resolved.log_level)

    if resolved.is_production and resolved.uses_placeholder_secret:
        raise RuntimeError(
            "SESSION_SECRET is still the placeholder value. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    @asynccontextmanager
    async def lifespan(instance: FastAPI) -> AsyncIterator[None]:
        # This doesn't actually connect yet, so the app still starts when Postgres
        # is down. The readiness check reports that instead.
        engine = build_engine(resolved)
        instance.state.engine = engine
        instance.state.sessionmaker = build_sessionmaker(engine)
        logger.info(
            "api.startup",
            extra={
                "env": resolved.app_env,
                "git_sha": resolved.git_sha,
                "version": __version__,
                "pooler_mode": resolved.db_pooler_mode,
            },
        )
        try:
            yield
        finally:
            await engine.dispose()
            logger.info("api.shutdown")

    app = FastAPI(
        title="IAM Control Plane",
        summary="SAML 2.0 and SCIM 2.0 identity control plane",
        version=__version__,
        # All under /api so Caddy needs one rule to cover the whole API, docs
        # included. The oauth2 redirect is spelled out because FastAPI otherwise
        # puts it at /docs/oauth2-redirect, outside that prefix, where it would
        # hit the frontend instead.
        docs_url="/api/docs",
        swagger_ui_oauth2_redirect_url="/api/docs/oauth2-redirect",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = resolved

    # No CORS middleware here, on purpose. The frontend is served from this same
    # address, so a cross-origin request means something is misconfigured and it
    # should fail loudly. See docs/adr/0003-single-origin.md.
    app.include_router(health.router, prefix="/api")
    app.include_router(me.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(groups.router, prefix="/api")
    app.include_router(applications.router, prefix="/api")
    app.include_router(identity_providers.router, prefix="/api")
    app.include_router(login_inspector.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")

    # No /api prefix. Providers post to these from the person's browser, so they're
    # part of the site rather than the JSON API, and Caddy proxies /saml/* on its
    # own rule.
    app.include_router(saml.router)

    # SAML login works now, but the development stand-in is still behind it for
    # requests that arrive without a session cookie. Say so on startup rather than
    # letting an environment run it quietly. See iam/security/actor.py.
    if not resolved.is_production and resolved.dev_actor_user_name:
        logger.warning(
            "auth.development_shim_active",
            extra={
                "detail": (
                    "Requests with no session cookie are identified by an "
                    "X-Dev-Actor header, falling back to DEV_ACTOR_USER_NAME. "
                    "This is impersonation, not authentication. It never runs in "
                    "production, and it goes once an identity provider is "
                    "registered. Unset DEV_ACTOR_USER_NAME to switch it off."
                ),
                "default_actor": resolved.dev_actor_user_name,
            },
        )

    return app


app = create_app()
