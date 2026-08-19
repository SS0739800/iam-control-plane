"""Two health checks: is the app running, and is it able to serve traffic.

Worth keeping separate. The first answers "should this container be restarted",
the second answers "should we send requests here". Roll them into one and a
two-second database hiccup starts restarting containers.
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
    """Is the app running. Doesn't check anything outside the process."""

    status: Literal["ok"] = "ok"
    env: str = Field(description="Which environment this is")
    version: str = Field(description="App version")
    git_sha: str = Field(description="The commit this build came from")


class Readiness(BaseModel):
    """Is the app able to do its job, i.e. can it reach the database."""

    status: Literal["ready", "degraded"]
    database: Literal["ok", "unreachable"]
    detail: str | None = Field(
        default=None,
        description="The kind of error, if any. Never the connection string.",
    )


@router.get("/health", response_model=Liveness, summary="Liveness probe")
async def liveness(settings: Annotated[Settings, Depends(app_settings)]) -> Liveness:
    """Say that the app is up.

    Doesn't touch the database, so a database outage can't get a perfectly healthy
    container killed. It's also cheap enough for the frontend to call on page load
    to wake the API up.
    """
    return Liveness(env=settings.app_env, version=__version__, git_sha=settings.git_sha)


@router.get(
    "/health/ready",
    response_model=Readiness,
    summary="Readiness probe",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": Readiness}},
)
async def readiness(request: Request, response: Response) -> Readiness:
    """Check that Postgres answers a trivial query.

    Returns 503 if it doesn't, so a load balancer stops sending traffic here
    instead of letting requests fail.
    """
    factory = request.app.state.sessionmaker

    try:
        async with factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        # Anything going wrong here means not ready. We return the error type but
        # not the message, since the message can contain the connection string.
        logger.warning("health.database_unreachable", exc_info=exc)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return Readiness(status="degraded", database="unreachable", detail=type(exc).__name__)

    return Readiness(status="ready", database="ok")
