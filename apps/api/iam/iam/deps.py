"""Bits and pieces that route handlers ask for.

Settings come off app.state rather than the cached get_settings() singleton. That
way a test can build an app with its own settings without having to clear caches
or reach into module globals.
"""

from __future__ import annotations

from typing import Annotated

# These need to be real imports, not TYPE_CHECKING ones. FastAPI reads the type
# hints on dependency functions when it starts, and it can't resolve a name that
# only exists for the type checker.
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.db import get_session


def app_settings(request: Request) -> Settings:
    """The settings this app was built with."""
    settings: Settings = request.app.state.settings
    return settings


SessionDep = Annotated[AsyncSession, Depends(get_session)]
"""A database session that lasts for one request."""

SettingsDep = Annotated[Settings, Depends(app_settings)]
"""This app's settings."""
