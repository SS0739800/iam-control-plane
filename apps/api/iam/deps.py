"""Shared FastAPI dependencies.

Settings are read off ``app.state`` rather than from the cached
:func:`iam.config.get_settings` singleton. That is what lets a test build an app
with its own settings without poking at module-level state or clearing caches.
"""

from __future__ import annotations

# Both imports must be available at runtime: FastAPI resolves dependency
# annotations with get_type_hints() at startup, and a TYPE_CHECKING-only import
# raises NameError there.
from fastapi import Request

from iam.config import Settings


def app_settings(request: Request) -> Settings:
    """The settings this application instance was created with."""
    settings: Settings = request.app.state.settings
    return settings
