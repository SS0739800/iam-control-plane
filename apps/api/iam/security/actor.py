"""Works out who is making the request.

Heads up: there is no real login yet. That arrives in P2 with SAML. Until then a
request says who it is with an X-Dev-Actor header naming a user. That is not
authentication, it's just asking nicely, so anyone could claim to be anyone.

Three things stop that being dangerous:

- resolve_actor refuses to run at all when APP_ENV is production. It doesn't read
  the header, doesn't fall back to anything. There's no setting to flip.
- The app logs a warning on startup while this is switched on, so nobody runs it
  without noticing.
- There's a test for the production refusal, so CI fails if someone deletes it.

In P2, resolve_actor stops reading the header and looks up a session from a cookie
instead. The function signature stays the same, so no route has to change.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.db import get_session
from iam.deps import app_settings
from iam.models.enums import PlatformRole
from iam.models.user import User
from iam.security.permissions import Permission, permissions_for

DEV_ACTOR_HEADER = "X-Dev-Actor"


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is making this request, and what they're allowed to do."""

    user_id: uuid.UUID
    user_name: str
    display_name: str
    role: PlatformRole
    permissions: frozenset[Permission]

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    @property
    def audit_label(self) -> str:
        """How this person's name appears in the audit log."""
        return f"{self.display_name} <{self.user_name}>"


def _forbid_in_production(settings: Settings) -> None:
    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "No authentication is configured. Real login arrives in P2 with "
                "SAML; the development actor header is never honoured in "
                "production."
            ),
        )


async def resolve_actor(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(app_settings)],
) -> Actor:
    """Figure out who is calling.

    Raises:
        HTTPException: 401 in production, since there's no real login yet. 401 if
            we can't tell who's calling. 403 if the account is switched off.
    """
    _forbid_in_production(settings)

    requested = request.headers.get(DEV_ACTOR_HEADER) or settings.dev_actor_user_name
    if not requested:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Send a {DEV_ACTOR_HEADER} header naming a user, or set " "DEV_ACTOR_USER_NAME."
            ),
        )

    user = await session.scalar(select(User).where(User.user_name == requested))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"No user with userName {requested!r}. Has the seed script run?",
        )

    # We keep deactivated users around so their history stays readable, but they
    # can't do anything. P4's "someone left, cut their access" flow leans on this.
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated.",
        )

    return Actor(
        user_id=user.id,
        user_name=user.user_name,
        display_name=user.display_name,
        role=user.platform_role,
        permissions=permissions_for(user.platform_role),
    )


CurrentActor = Annotated[Actor, Depends(resolve_actor)]
"""Inject the current actor into a route handler."""
