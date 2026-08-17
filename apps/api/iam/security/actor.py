"""Works out who is making the request.

The real answer comes from the session cookie. It holds a random token, we look
up its hash, and that gives us a session row and the person it belongs to. A
session that's been revoked, has expired, or has sat idle too long is the same as
no session at all.

There is still a development stand-in behind it, and it's worth being precise
about what it is. With no session cookie, a request outside production can say
who it is with an X-Dev-Actor header naming a user, falling back to
DEV_ACTOR_USER_NAME. That is not authentication, it's asking nicely.

It's still here because the console would otherwise be unusable until an identity
provider is registered and its certificate stored, and that's the next piece of
work rather than this one. It goes when authentik is wired up.

Four things stop it being dangerous in the meantime:

- The cookie is checked first. A real session always wins, so the stand-in can
  never override or downgrade somebody who is properly signed in.
- Production never reaches it. Not "switched off by a setting" — the branch
  returns before it, and there is no configuration that changes that.
- The app logs a warning on startup while it's switched on.
- There's a test for the production refusal, so CI fails if someone deletes it.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access.roles import expire_due_grants_for
from iam.config import Settings
from iam.db import get_session
from iam.deps import app_settings
from iam.models.enums import PlatformRole
from iam.models.user import User
from iam.saml.sessions import (
    SESSION_TOUCH_INTERVAL,
    RevokedReason,
    lookup_session,
    revoke_all_for_user,
    touch_session,
)
from iam.security.permissions import Permission, permissions_for

logger = logging.getLogger(__name__)

DEV_ACTOR_HEADER = "X-Dev-Actor"

NOT_SIGNED_IN = "Not signed in. Start at /saml/login."


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is making this request, and what they're allowed to do."""

    user_id: uuid.UUID
    user_name: str
    display_name: str
    role: PlatformRole
    permissions: frozenset[Permission]
    session_id: uuid.UUID | None = None
    """The session they're signed in on, or None for the development stand-in."""

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    @property
    def audit_label(self) -> str:
        """How this person's name appears in the audit log."""
        return f"{self.display_name} <{self.user_name}>"


async def _drop_expired_role(db: AsyncSession, user: User, *, now: dt.datetime) -> None:
    """Take away a role whose end date has passed, before we act on it.

    The cached role on the user's row is only refreshed when somebody writes a
    grant, and expiry is the one change that happens with nobody writing anything.
    A nightly sweep would leave a window where an expired admin is still an admin,
    and that window is exactly the thing the expiry date was meant to close.

    Only runs for people the cache says are privileged. Everybody else is already
    an employee, so there is nothing an expiry could take away, and skipping them
    keeps this off the hot path for almost every request.
    """
    if user.platform_role == PlatformRole.EMPLOYEE:
        return

    if await expire_due_grants_for(db, user, now=now):
        await db.commit()
        logger.info(
            "auth.expired_role_dropped",
            extra={"user_name": user.user_name, "now_role": str(user.platform_role)},
        )


def _actor_for(user: User, *, session_id: uuid.UUID | None = None) -> Actor:
    return Actor(
        user_id=user.id,
        user_name=user.user_name,
        display_name=user.display_name,
        role=user.platform_role,
        permissions=permissions_for(user.platform_role),
        session_id=session_id,
    )


async def _actor_from_cookie(
    request: Request,
    db: AsyncSession,
    settings: Settings,
    *,
    now: dt.datetime,
) -> Actor | None:
    """Who the session cookie says this is, or None if it doesn't say.

    Returning None rather than raising is deliberate for everything except a
    deactivated account. A missing or dead session means "not signed in", and it's
    the caller's job to decide whether that's an error or just the anonymous case.

    Raises:
        HTTPException: 403 if the account has been switched off.
    """
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None

    live = await lookup_session(db, token, now=now)
    if live is None:
        return None

    user = await db.get(User, live.user_id)
    if user is None:
        # The person's row is gone but their session isn't. Shouldn't happen, since
        # deleting a user cascades to their sessions, but treating it as "not
        # signed in" is the only safe reading.
        logger.warning("auth.session_without_user", extra={"session_id": str(live.id)})
        return None

    if not user.active:
        # Cut the rest of their sessions too, not just this one. They were
        # deactivated at some point and this is the moment we noticed; leaving
        # their other browsers signed in would make the deactivation a lie.
        # P4 does this at the moment of deactivation, and this is the backstop.
        ended = await revoke_all_for_user(
            db, user.id, reason=RevokedReason.USER_DEACTIVATED, now=now
        )
        await db.commit()
        logger.info(
            "auth.deactivated_sessions_revoked",
            extra={"user_name": user.user_name, "sessions_ended": ended},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated.",
        )

    # Before the role on this row is used for anything.
    await _drop_expired_role(db, user, now=now)

    # Only when it's actually gone stale. See SESSION_TOUCH_INTERVAL — otherwise
    # this would be a database write on every single request.
    if now - live.last_seen_at >= SESSION_TOUCH_INTERVAL:
        await touch_session(db, live, now=now)
        await db.commit()

    return _actor_for(user, session_id=live.id)


async def _actor_from_dev_header(
    request: Request,
    db: AsyncSession,
    settings: Settings,
    *,
    now: dt.datetime,
) -> Actor:
    """The development stand-in. Never reached in production — see the module docstring.

    Raises:
        HTTPException: 401 if no user is named or the named one doesn't exist. 403
            if the account is switched off.
    """
    requested = request.headers.get(DEV_ACTOR_HEADER) or settings.dev_actor_user_name
    if not requested:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Not signed in. Sign in at /saml/login, send a {DEV_ACTOR_HEADER} "
                "header naming a user, or set DEV_ACTOR_USER_NAME."
            ),
        )

    user = await db.scalar(select(User).where(User.user_name == requested))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"No user with userName {requested!r}. Has the seed script run?",
        )

    # We keep deactivated users around so their history stays readable, but they
    # can't do anything. The leaver flow leans on this.
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated.",
        )

    # Expiry applies here too. The stand-in is a way to skip logging in, not a way
    # to keep a role somebody's grant already gave back.
    await _drop_expired_role(db, user, now=now)

    return _actor_for(user)


async def resolve_actor(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(app_settings)],
) -> Actor:
    """Figure out who is calling.

    The cookie first, always. The development stand-in only gets a look in when
    there is no session to be had, and only outside production.

    Raises:
        HTTPException: 401 if we can't tell who's calling. 403 if the account is
            switched off.
    """
    now = dt.datetime.now(dt.UTC)

    signed_in = await _actor_from_cookie(request, session, settings, now=now)
    if signed_in is not None:
        return signed_in

    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=NOT_SIGNED_IN,
        )

    return await _actor_from_dev_header(request, session, settings, now=now)


CurrentActor = Annotated[Actor, Depends(resolve_actor)]
"""Inject the current actor into a route handler."""
