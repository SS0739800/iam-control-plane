"""Keeping someone signed in after they've logged in.

Sessions are rows in a table, not signed tokens handed to the browser. That's a
deliberate trade: a signed token means no database lookup on every request, but you
can't take one back once you've issued it. P4 has to cut someone off the moment
they're deactivated, and you can't un-issue a token — you can delete a row.

The browser gets a long random string in a cookie. We store only its hash, the
same way passwords are handled. Someone who reads this table still can't sign in as
anybody, because the hash won't turn back into the cookie.

No xmlsec here, so this is testable anywhere.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid

from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.models.saml import SamlSession

SESSION_COOKIE_TOKEN_BYTES = 32
"""Length of the random value in the cookie. Guessing one is guessing a login."""

SESSION_LIFETIME = dt.timedelta(hours=8)
"""How long someone stays signed in. Roughly a working day, so people aren't
logged out mid-task, but a forgotten session on a shared machine doesn't last
forever."""

SESSION_IDLE_TIMEOUT = dt.timedelta(hours=1)
"""How long a session survives with nothing happening on it."""

SESSION_TOUCH_INTERVAL = dt.timedelta(minutes=1)
"""How stale the last-seen time has to be before we bother writing a new one.

Updating it on literally every request would mean a write for every page load,
every poll, every image. The idle timeout is an hour, so being up to a minute
behind costs nothing and turns a per-request write into an occasional one.
"""


class RevokedReason:
    """Why a session ended. Recorded so the audit log can say which."""

    SIGNED_OUT = "signed_out"
    SIGNED_OUT_ELSEWHERE = "signed_out_at_provider"
    USER_DEACTIVATED = "user_deactivated"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"


def new_session_token() -> str:
    """The value that goes in the cookie. Never stored anywhere."""
    return secrets.token_urlsafe(SESSION_COOKIE_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """What we store instead of the cookie value.

    Plain SHA-256 rather than a slow password hash, on purpose. Slow hashing exists
    to make guessing human-chosen passwords expensive. This token is 32 random
    bytes, so there is nothing to guess, and doing it slowly would just add work to
    every single request.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_session(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    idp_slug: str,
    name_id: str,
    name_id_format: str | None,
    session_index: str | None,
    issued_at: dt.datetime,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[SamlSession, str]:
    """Sign someone in, and return the session plus the cookie value.

    The token is returned rather than stored, because this is the only moment it
    exists in readable form. Once this returns, only its hash is written down.
    """
    token = new_session_token()

    session = SamlSession(
        token_hash=hash_token(token),
        user_id=user_id,
        idp_slug=idp_slug,
        name_id=name_id,
        name_id_format=name_id_format,
        session_index=session_index,
        created_at=issued_at,
        last_seen_at=issued_at,
        expires_at=issued_at + SESSION_LIFETIME,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    await db.flush()
    return session, token


async def find_by_token(db: AsyncSession, token: str) -> SamlSession | None:
    """Find whatever session a cookie value points at, alive or not.

    Signing out wants this one rather than lookup_session: somebody whose session
    went idle an hour ago still clicked the button, and their row should still be
    marked as ended rather than left open forever.
    """
    found: SamlSession | None = await db.scalar(
        select(SamlSession).where(SamlSession.token_hash == hash_token(token))
    )
    return found


async def lookup_session(db: AsyncSession, token: str, *, now: dt.datetime) -> SamlSession | None:
    """Find the live session for a cookie value, if there is one.

    Returns nothing for a session that's been revoked, has expired, or has been
    sitting idle too long. Those are all "not signed in" from the caller's point of
    view; the difference only matters to the audit log.
    """
    found = await find_by_token(db, token)
    if found is None:
        return None

    if found.revoked_at is not None:
        return None

    if found.expires_at <= now:
        return None

    if now - found.last_seen_at > SESSION_IDLE_TIMEOUT:
        return None

    return found


async def touch_session(db: AsyncSession, session: SamlSession, *, now: dt.datetime) -> None:
    """Mark a session as recently used, so the idle timeout doesn't catch it.

    Written straight to the row rather than through the loaded object, so it
    doesn't fight with anything else the request is doing to that session.
    """
    await db.execute(
        update(SamlSession).where(SamlSession.id == session.id).values(last_seen_at=now)
    )


async def revoke_session(
    db: AsyncSession, session: SamlSession, *, reason: str, now: dt.datetime
) -> None:
    """End one session.

    Marked rather than deleted, so "signed out at 14:32, because they were
    deactivated" is still answerable afterwards. An audit log that loses the thing
    it's describing isn't much of an audit log.
    """
    await db.execute(
        update(SamlSession)
        .where(SamlSession.id == session.id, SamlSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )


async def revoke_all_for_user(
    db: AsyncSession, user_id: uuid.UUID, *, reason: str, now: dt.datetime
) -> int:
    """End every live session belonging to one person.

    This is the function P4's "someone left, cut their access" flow calls. It is
    the reason sessions are rows in the first place: with signed tokens there would
    be nothing here to do, and the person would stay signed in until their token
    ran out on its own.

    Returns how many were ended, so the audit entry can say.
    """
    result = await db.execute(
        update(SamlSession)
        .where(SamlSession.user_id == user_id, SamlSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )
    return int(result.rowcount or 0)


async def revoke_by_session_index(
    db: AsyncSession, *, idp_slug: str, session_index: str, now: dt.datetime
) -> int:
    """End the session the provider is telling us about.

    When someone signs out at the provider, it tells every application they were
    signed into. It identifies the session by its own name for it, which is why we
    stored that at login.
    """
    result = await db.execute(
        update(SamlSession)
        .where(
            SamlSession.idp_slug == idp_slug,
            SamlSession.session_index == session_index,
            SamlSession.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoked_reason=RevokedReason.SIGNED_OUT_ELSEWHERE)
    )
    return int(result.rowcount or 0)


# ----------------------------------------------------------------- the cookie


def set_session_cookie(response: Response, token: str, *, settings: Settings) -> None:
    """Put the session token in a cookie on this response.

    Every flag here is doing something:

    ``httponly`` keeps JavaScript from reading it, so a cross-site scripting bug
    somewhere in the console doesn't hand out live sessions.

    ``samesite="lax"`` is what stops another site making a request as the signed-in
    person. Lax rather than Strict because the login itself ends in a redirect back
    from the provider, and a Strict cookie isn't sent on that first arrival — the
    person would land on the page still looking logged out.

    Note that this is set on the response to a cross-site POST from the provider,
    which is fine: SameSite governs when a cookie is *sent*, not whether it can be
    set. The redirect that follows is a normal top-level navigation to our own
    site, and Lax sends the cookie on those.

    ``secure`` follows the address we're served on, so local http development
    works while anything real gets an https-only cookie.
    """
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.base_url.startswith("https://"),
    )


def clear_session_cookie(response: Response, *, settings: Settings) -> None:
    """Remove the session cookie.

    The flags have to match the ones it was set with, or the browser treats it as
    a different cookie and quietly leaves the original in place.
    """
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.base_url.startswith("https://"),
    )
