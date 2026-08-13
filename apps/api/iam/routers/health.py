"""Liveness and readiness probes.

The split matters operationally: liveness answers "should this container be
restarted", readiness answers "should traffic be routed here". Conflating them
means a brief database blip triggers a restart loop.
"""

from __future__ import annotations

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from iam import __version__
from iam.config import Settings
from iam.deps import app_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ops"])


class Liveness(BaseModel):
    """Process-level health. No external dependencies consulted."""

    status: Literal["ok"] = "ok"
    env: str = Field(description="Deployment environment")
    version: str = Field(description="Application version")
    git_sha: str = Field(description="Commit the running image was built from")


class Readiness(BaseModel):
    """Dependency-level health."""

    status: Literal["ready", "degraded"]
    database: Literal["ok", "unreachable"]
    detail: str | None = Field(
        default=None,
        description="Exception class name when degraded. Never the connection string.",
    )


@router.get("/health", response_model=Liveness, summary="Liveness probe")
async def liveness(settings: Annotated[Settings, Depends(app_settings)]) -> Liveness:
    """Report that the process is serving.

    Deliberately does not touch the database, so that a database outage does not
    get a healthy container killed. Also makes this the probe the frontend can
    call to warm the API without cost.
    """
    return Liveness(env=settings.app_env, version=__version__, git_sha=settings.git_sha)


@router.get(
    "/health/ready",
    response_model=Readiness,
    summary="Readiness probe",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": Readiness}},
)
async def readiness(request: Request, response: Response) -> Readiness:
    """Verify Postgres answers a trivial query.

    Returns 503 when it does not, so a load balancer drains this instance
    instead of serving errors.
    """
    factory = request.app.state.sessionmaker

    try:
        async with factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        # Any failure here means not ready; the class name is enough to
        # diagnose without leaking credentials into a public response body.
        logger.warning("health.database_unreachable", exc_info=exc)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return Readiness(status="degraded", database="unreachable", detail=type(exc).__name__)

    return Readiness(status="ready", database="ok")
