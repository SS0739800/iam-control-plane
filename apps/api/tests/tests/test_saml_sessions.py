"""Tests for the session store: issuing, looking up, and ending sessions.

The token tests run anywhere. The rest need Postgres and are marked integration.

No xmlsec involved either way — sessions are rows and cookies, and none of that
touches XML.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.models.enums import IdentitySource, PlatformRole
from iam.models.saml import SamlSession
from iam.models.user import User
from iam.saml.sessions import (
    SESSION_IDLE_TIMEOUT,
    SESSION_LIFETIME,
    RevokedReason,
    clear_session_cookie,
    create_session,
    find_by_token,
    lookup_session,
    new_session_token,
    revoke_all_for_user,
    revoke_by_session_index,
    revoke_session,
    set_session_cookie,
    touch_session,
)
from iam.tokens import hash_token

NOW = dt.datetime(2026, 8, 14, 12, 0, 0, tzinfo=dt.UTC)


# ------------------------------------------------------------------ the token


def test_tokens_are_unique_and_long() -> None:
    """Guessing one is guessing a login, so there has to be nothing to guess."""
    tokens = {new_session_token() for _ in range(200)}

    assert len(tokens) == 200
    assert all(len(token) >= 32 for token in tokens)


def test_the_hash_is_not_the_token() -> None:
    """Someone who reads the sessions table must not be able to sign in as anybody."""
    token = new_session_token()

    assert hash_token(token) != token
    assert token not in hash_token(token)


def test_the_same_token_always_hashes_the_same() -> None:
    """Otherwise nobody could ever be looked up twice."""
    token = new_session_token()

    assert hash_token(token) == hash_token(token)


# ----------------------------------------------------------------- the cookie


def cookie_settings(base_url: str = "http://localhost:8080") -> Settings:
    return Settings(
        app_env="ci",
        base_url=base_url,
        session_secret="test-secret-deliberately-not-the-placeholder",
        database_url="postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent",
    )


def test_the_cookie_is_locked_down() -> None:
    response = Response()

    set_session_cookie(response, "a-token", settings=cookie_settings())

    header = response.headers["set-cookie"]
    assert "iam_session=a-token" in header
    assert "HttpOnly" in header
    assert "samesite=lax" in header.lower()
    assert "Path=/" in header
    assert f"Max-Age={int(SESSION_LIFETIME.total_seconds())}" in header


def test_the_cookie_is_https_only_when_we_are_served_over_https() -> None:
    """And not on plain http, or local development would silently stop working."""
    over_http = Response()
    over_https = Response()

    set_session_cookie(over_http, "t", settings=cookie_settings("http://localhost:8080"))
    set_session_cookie(over_https, "t", settings=cookie_settings("https://iam.demo.local"))

    assert "Secure" not in over_http.headers["set-cookie"]
    assert "Secure" in over_https.headers["set-cookie"]


def test_clearing_the_cookie_matches_how_it_was_set() -> None:
    """Different flags and the browser treats it as a different cookie, leaving the
    original one sitting there."""
    response = Response()

    clear_session_cookie(response, settings=cookie_settings())

    header = response.headers["set-cookie"]
    assert "iam_session=" in header
    assert "Path=/" in header
    assert "HttpOnly" in header


# ------------------------------------------------------ issuing and looking up


async def make_user(db: AsyncSession, suffix: str) -> User:
    user = User(
        user_name=f"session.{suffix}@demo.local",
        email=f"session.{suffix}@demo.local",
        display_name=f"Session Tester {suffix}",
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.JIT,
    )
    db.add(user)
    await db.flush()
    return user


async def make_session(
    db: AsyncSession, *, issued_at: dt.datetime = NOW, session_index: str | None = None
) -> tuple[SamlSession, str, User]:
    suffix = uuid.uuid4().hex[:12]
    user = await make_user(db, suffix)
    session, token = await create_session(
        db,
        user_id=user.id,
        idp_slug=f"idp-{suffix}",
        name_id=f"persistent-{suffix}",
        name_id_format=None,
        session_index=session_index,
        issued_at=issued_at,
    )
    return session, token, user


@pytest.mark.integration
async def test_only_the_hash_is_stored(db_session: AsyncSession) -> None:
    session, token, _ = await make_session(db_session)

    assert session.token_hash == hash_token(token)
    assert session.token_hash != token


@pytest.mark.integration
async def test_a_fresh_session_is_found(db_session: AsyncSession) -> None:
    _, token, _ = await make_session(db_session)

    assert await lookup_session(db_session, token, now=NOW) is not None


@pytest.mark.integration
async def test_a_token_nobody_issued_finds_nothing(db_session: AsyncSession) -> None:
    assert await lookup_session(db_session, "not-a-real-token", now=NOW) is None


@pytest.mark.integration
async def test_a_revoked_session_is_not_found(db_session: AsyncSession) -> None:
    """This is the whole reason sessions are rows and not signed tokens."""
    session, token, _ = await make_session(db_session)

    await revoke_session(db_session, session, reason=RevokedReason.SIGNED_OUT, now=NOW)

    assert await lookup_session(db_session, token, now=NOW) is None


@pytest.mark.integration
async def test_an_expired_session_is_not_found(db_session: AsyncSession) -> None:
    _, token, _ = await make_session(db_session)

    later = NOW + SESSION_LIFETIME + dt.timedelta(minutes=1)

    assert await lookup_session(db_session, token, now=later) is None


@pytest.mark.integration
async def test_a_session_left_idle_is_not_found(db_session: AsyncSession) -> None:
    """Still inside its eight hours, but nothing has happened on it for an hour."""
    _, token, _ = await make_session(db_session)

    idle = NOW + SESSION_IDLE_TIMEOUT + dt.timedelta(minutes=1)

    assert await lookup_session(db_session, token, now=idle) is None


@pytest.mark.integration
async def test_being_used_keeps_a_session_from_going_idle(db_session: AsyncSession) -> None:
    session, token, _ = await make_session(db_session)

    half_way = NOW + dt.timedelta(minutes=45)
    await touch_session(db_session, session, now=half_way)
    db_session.expire_all()

    still_going = half_way + dt.timedelta(minutes=45)
    assert await lookup_session(db_session, token, now=still_going) is not None


@pytest.mark.integration
async def test_find_by_token_returns_a_dead_session_too(db_session: AsyncSession) -> None:
    """Signing out needs this: an hour-idle session should still get marked ended
    rather than left open."""
    session, token, _ = await make_session(db_session)
    await revoke_session(db_session, session, reason=RevokedReason.SIGNED_OUT, now=NOW)
    db_session.expire_all()

    found = await find_by_token(db_session, token)

    assert found is not None
    assert found.revoked_at is not None


# ---------------------------------------------------------------- ending them


@pytest.mark.integration
async def test_revoking_records_why(db_session: AsyncSession) -> None:
    """An audit log that loses the thing it's describing isn't much of one."""
    session, _, _ = await make_session(db_session)
    session_id = session.id

    await revoke_session(db_session, session, reason=RevokedReason.USER_DEACTIVATED, now=NOW)
    db_session.expire_all()

    stored = await db_session.get(SamlSession, session_id)
    assert stored is not None
    assert stored.revoked_reason == RevokedReason.USER_DEACTIVATED
    assert stored.revoked_at == NOW


@pytest.mark.integration
async def test_revoking_twice_does_not_rewrite_the_first_reason(
    db_session: AsyncSession,
) -> None:
    """When they were cut off matters. A second call must not move the timestamp."""
    session, _, _ = await make_session(db_session)
    session_id = session.id

    await revoke_session(db_session, session, reason=RevokedReason.SIGNED_OUT, now=NOW)
    await revoke_session(
        db_session,
        session,
        reason=RevokedReason.USER_DEACTIVATED,
        now=NOW + dt.timedelta(hours=1),
    )
    db_session.expire_all()

    stored = await db_session.get(SamlSession, session_id)
    assert stored is not None
    assert stored.revoked_reason == RevokedReason.SIGNED_OUT
    assert stored.revoked_at == NOW


@pytest.mark.integration
async def test_cutting_someone_off_ends_every_session_they_have(
    db_session: AsyncSession,
) -> None:
    """The function P4's "someone left" flow calls. With signed tokens there would
    be nothing here to do and they'd stay signed in until the token ran out."""
    suffix = uuid.uuid4().hex[:12]
    user = await make_user(db_session, suffix)
    tokens = []
    for index in range(3):
        _, token = await create_session(
            db_session,
            user_id=user.id,
            idp_slug=f"idp-{suffix}",
            name_id=f"persistent-{suffix}",
            name_id_format=None,
            session_index=f"index-{index}",
            issued_at=NOW,
        )
        tokens.append(token)

    ended = await revoke_all_for_user(
        db_session, user.id, reason=RevokedReason.USER_DEACTIVATED, now=NOW
    )
    db_session.expire_all()

    assert ended == 3
    for token in tokens:
        assert await lookup_session(db_session, token, now=NOW) is None


@pytest.mark.integration
async def test_the_provider_can_end_the_session_it_names(db_session: AsyncSession) -> None:
    """When someone signs out at the provider it tells us by its own name for the
    session, which is why we stored that at login."""
    session, token, _ = await make_session(db_session, session_index="index-abc")

    ended = await revoke_by_session_index(
        db_session, idp_slug=session.idp_slug, session_index="index-abc", now=NOW
    )
    db_session.expire_all()

    assert ended == 1
    assert await lookup_session(db_session, token, now=NOW) is None


@pytest.mark.integration
async def test_one_persons_logout_does_not_touch_anybody_else(
    db_session: AsyncSession,
) -> None:
    _, mine, _ = await make_session(db_session)
    other_session, theirs, _ = await make_session(db_session)

    await revoke_session(db_session, other_session, reason=RevokedReason.SIGNED_OUT, now=NOW)
    db_session.expire_all()

    assert await lookup_session(db_session, mine, now=NOW) is not None
    assert await lookup_session(db_session, theirs, now=NOW) is None


@pytest.mark.integration
async def test_revoked_sessions_are_kept_not_deleted(db_session: AsyncSession) -> None:
    """ "Signed out at 14:32, because they were deactivated" has to stay answerable."""
    session, _, _ = await make_session(db_session)
    # Read the id before expiring, or getting at it afterwards is itself a query.
    session_id = session.id

    await revoke_session(db_session, session, reason=RevokedReason.SIGNED_OUT, now=NOW)
    db_session.expire_all()

    still_there = await db_session.scalar(select(SamlSession).where(SamlSession.id == session_id))
    assert still_there is not None
