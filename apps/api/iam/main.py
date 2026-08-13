"""FastAPI application factory.

``create_app`` takes optional settings so tests can build an isolated instance.
The module-level ``app`` is what uvicorn imports in production.
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
from iam.routers import health

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Args:
        settings: Overrides the environment-derived settings. Tests pass their
            own; production leaves this ``None``.
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
        # SQLAlchemy connects lazily, so this does not fail when Postgres is
        # down — readiness reports that instead of the process refusing to boot.
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
        # Kept under /api so Caddy's single-origin config needs one rule for the
        # whole API surface, docs and schema included. The oauth2 redirect is
        # explicit because FastAPI otherwise defaults it to /docs/oauth2-redirect,
        # which falls outside the proxied prefix and lands on the SPA.
        docs_url="/api/docs",
        swagger_ui_oauth2_redirect_url="/api/docs/oauth2-redirect",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = resolved

    # No CORSMiddleware, deliberately. The SPA is served from this same origin,
    # so a cross-origin request is a misconfiguration and should fail rather
    # than be quietly permitted. See docs/adr/0003-single-origin.md.
    app.include_router(health.router, prefix="/api")

    return app


app = create_app()
