"""Tests for role grants and the cached role on the user row.

The design is "grants are the truth, the column is a cache", which is only safe if
the cache cannot drift. Most of what follows is checking that it can't:

- every path that changes a grant updates the column
- the database refuses two live grants for one person
- an expired grant stops counting the moment it expires, not when a sweep runs
- find_drift comes back empty

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access import (
    Granter,
    RoleGrantRefused,
    effective_role,
    expire_due_grants,
    find_drift,
    grant_role,
    history,
    live_grant,
    revoke_for_leaver,
    revoke_role,
)
from iam.models.access import RevokedGrantReason, RoleGrant
from iam.models.enums import GrantSource, IdentitySource, PlatformRole
from iam.models.user import User

pytestmark = pytest.mark.integration

NOW = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)
LATER = NOW + dt.timedelta(days=7)

ADMIN = Granter(user_id=None, label="Priya Nair <priya@demo.local>")


async def make_user(db: AsyncSession, *, active: bool = True) -> User:
    suffix = uuid.uuid4().hex[:12]
    user = User(
        user_name=f"grant.{suffix}@demo.local",
        email=f"grant.{suffix}@demo.local",
        display_name=f"Grant Tester {suffix}",
        active=active,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.MANUAL,
    )
    db.add(user)
    await db.flush()
    return user


# --------------------------------------------------------------- granting


@pytest.mark.integration
async def test_granting_sets_the_role_and_the_cache(db_session: AsyncSession) -> None:
    user = await make_user(db_session)

    grant = await grant_role(db_session, user, role=PlatformRole.HELPDESK, granter=ADMIN, now=NOW)

    assert grant.role == PlatformRole.HELPDESK
    assert user.platform_role == PlatformRole.HELPDESK
    assert await effective_role(db_session, user.id, now=NOW) == PlatformRole.HELPDESK


@pytest.mark.integration
async def test_the_grant_records_who_and_why(db_session: AsyncSession) -> None:
    """The whole reason this table exists. "Because somebody did" is not an answer."""
    user = await make_user(db_session)

    grant = await grant_role(
        db_session,
        user,
        role=PlatformRole.ADMIN,
        granter=ADMIN,
        now=NOW,
        reason="Covering the migration weekend",
    )

    assert grant.granted_by_label == ADMIN.label
    assert grant.reason == "Covering the migration weekend"
    assert grant.source == GrantSource.DIRECT


@pytest.mark.integration
async def test_granting_a_second_role_supersedes_the_first(db_session: AsyncSession) -> None:
    """Roles don't stack. Helpdesk plus auditor quietly adding up to almost-admin is
    exactly the kind of privilege nobody granted that this table exists to prevent."""
    user = await make_user(db_session)

    first = await grant_role(db_session, user, role=PlatformRole.HELPDESK, granter=ADMIN, now=NOW)
    second = await grant_role(db_session, user, role=PlatformRole.AUDITOR, granter=ADMIN, now=LATER)

    assert first.revoked_at == LATER
    assert first.revoked_reason == RevokedGrantReason.SUPERSEDED
    assert second.revoked_at is None
    assert user.platform_role == PlatformRole.AUDITOR


@pytest.mark.integration
async def test_regranting_the_same_role_changes_nothing(db_session: AsyncSession) -> None:
    """A rule re-firing every sync shouldn't fill the history with identical rows."""
    user = await make_user(db_session)

    first = await grant_role(db_session, user, role=PlatformRole.AUDITOR, granter=ADMIN, now=NOW)
    again = await grant_role(db_session, user, role=PlatformRole.AUDITOR, granter=ADMIN, now=LATER)

    assert again.id == first.id
    assert len(await history(db_session, user.id)) == 1


@pytest.mark.integration
async def test_employee_cannot_be_granted(db_session: AsyncSession) -> None:
    """It's the absence of a grant, not a grant. Storing one would mean two ways to
    say the same thing and a question about which wins."""
    user = await make_user(db_session)

    with pytest.raises(RoleGrantRefused, match="Revoke their current role"):
        await grant_role(db_session, user, role=PlatformRole.EMPLOYEE, granter=ADMIN, now=NOW)


@pytest.mark.integration
async def test_an_expiry_in_the_past_is_refused(db_session: AsyncSession) -> None:
    """It would create a grant that never applied, which is a typo, not an intention."""
    user = await make_user(db_session)

    with pytest.raises(RoleGrantRefused, match="already passed"):
        await grant_role(
            db_session,
            user,
            role=PlatformRole.ADMIN,
            granter=ADMIN,
            now=NOW,
            expires_at=NOW - dt.timedelta(days=1),
        )


@pytest.mark.integration
async def test_a_deactivated_person_cannot_be_granted_anything(
    db_session: AsyncSession,
) -> None:
    """Either a mistake or the first half of an attack. Reactivating is a
    separate step."""
    user = await make_user(db_session, active=False)

    with pytest.raises(RoleGrantRefused, match="deactivated"):
        await grant_role(db_session, user, role=PlatformRole.ADMIN, granter=ADMIN, now=NOW)


@pytest.mark.integration
async def test_the_database_refuses_two_live_grants(db_session: AsyncSession) -> None:
    """The constraint is in Postgres, not just in Python, because two simultaneous
    grants would otherwise both read "nothing here" and both insert."""
    user = await make_user(db_session)
    await grant_role(db_session, user, role=PlatformRole.HELPDESK, granter=ADMIN, now=NOW)

    # Bypasses the service layer — this is what a second request racing the
    # first would do.
    db_session.add(
        RoleGrant(
            user_id=user.id,
            role=PlatformRole.ADMIN,
            source=GrantSource.DIRECT,
            granted_by_label="a racing request",
        )
    )

    with pytest.raises(IntegrityError):
        await db_session.flush()

    await db_session.rollback()


# --------------------------------------------------------------- revoking


@pytest.mark.integration
async def test_revoking_puts_them_back_to_employee(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    await grant_role(db_session, user, role=PlatformRole.ADMIN, granter=ADMIN, now=NOW)

    revoked = await revoke_role(db_session, user, granter=ADMIN, now=LATER)

    assert revoked is not None
    assert revoked.revoked_reason == RevokedGrantReason.REVOKED
    assert user.platform_role == PlatformRole.EMPLOYEE
    assert await live_grant(db_session, user.id, now=LATER) is None


@pytest.mark.integration
async def test_the_revoked_grant_is_kept(db_session: AsyncSession) -> None:
    """ "She was an admin for three weeks in March" has to stay answerable."""
    user = await make_user(db_session)
    await grant_role(db_session, user, role=PlatformRole.ADMIN, granter=ADMIN, now=NOW)
    await revoke_role(db_session, user, granter=ADMIN, now=LATER)

    past = await history(db_session, user.id)

    assert len(past) == 1
    assert past[0].role == PlatformRole.ADMIN
    assert past[0].revoked_at == LATER


@pytest.mark.integration
async def test_revoking_when_there_is_nothing_to_revoke(db_session: AsyncSession) -> None:
    """The end state is what was asked for, so this isn't an error."""
    user = await make_user(db_session)

    assert await revoke_role(db_session, user, granter=ADMIN, now=NOW) is None
    assert user.platform_role == PlatformRole.EMPLOYEE


@pytest.mark.integration
async def test_revoking_repairs_a_cache_that_was_wrong(db_session: AsyncSession) -> None:
    """If the column says admin and no grant backs it, this is where that gets
    fixed rather than staying a permanent lie."""
    user = await make_user(db_session)
    user.platform_role = PlatformRole.ADMIN  # as if somebody had hand-edited it
    await db_session.flush()

    await revoke_role(db_session, user, granter=ADMIN, now=NOW)

    assert user.platform_role == PlatformRole.EMPLOYEE


@pytest.mark.integration
async def test_the_leaver_flow_says_why_the_access_ended(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    await grant_role(db_session, user, role=PlatformRole.HELPDESK, granter=ADMIN, now=NOW)

    revoked = await revoke_for_leaver(db_session, user, granter=ADMIN, now=LATER)

    assert revoked is not None
    assert revoked.revoked_reason == RevokedGrantReason.USER_DEACTIVATED


# ---------------------------------------------------------------- expiry


@pytest.mark.integration
async def test_an_expired_grant_stops_counting_immediately(db_session: AsyncSession) -> None:
    """Not when a sweep gets round to it. The window between "expired" and
    "noticed" is the thing the expiry date was meant to close."""
    user = await make_user(db_session)
    await grant_role(
        db_session,
        user,
        role=PlatformRole.ADMIN,
        granter=ADMIN,
        now=NOW,
        expires_at=NOW + dt.timedelta(hours=1),
    )

    just_before = NOW + dt.timedelta(minutes=59)
    just_after = NOW + dt.timedelta(hours=1, minutes=1)

    assert await effective_role(db_session, user.id, now=just_before) == PlatformRole.ADMIN
    assert await effective_role(db_session, user.id, now=just_after) == PlatformRole.EMPLOYEE


@pytest.mark.integration
async def test_the_sweep_revokes_what_is_due_and_fixes_the_cache(
    db_session: AsyncSession,
) -> None:
    user = await make_user(db_session)
    # Read the id before expiring, or getting at it afterwards is itself a query.
    user_id = user.id
    await grant_role(
        db_session,
        user,
        role=PlatformRole.ADMIN,
        granter=ADMIN,
        now=NOW,
        expires_at=NOW + dt.timedelta(hours=1),
    )

    ended = await expire_due_grants(db_session, now=NOW + dt.timedelta(days=1))
    db_session.expire_all()

    assert ended >= 1
    refreshed = await db_session.get(User, user_id)
    assert refreshed is not None
    assert refreshed.platform_role == PlatformRole.EMPLOYEE

    stored = await db_session.scalar(select(RoleGrant).where(RoleGrant.user_id == user_id))
    assert stored is not None
    assert stored.revoked_reason == RevokedGrantReason.EXPIRED


@pytest.mark.integration
async def test_the_sweep_leaves_grants_that_have_not_expired(
    db_session: AsyncSession,
) -> None:
    user = await make_user(db_session)
    await grant_role(
        db_session,
        user,
        role=PlatformRole.ADMIN,
        granter=ADMIN,
        now=NOW,
        expires_at=NOW + dt.timedelta(days=30),
    )

    await expire_due_grants(db_session, now=NOW + dt.timedelta(days=1))

    assert await effective_role(db_session, user.id, now=NOW + dt.timedelta(days=1)) == (
        PlatformRole.ADMIN
    )


@pytest.mark.integration
async def test_a_grant_with_no_end_date_never_expires(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    await grant_role(db_session, user, role=PlatformRole.AUDITOR, granter=ADMIN, now=NOW)

    await expire_due_grants(db_session, now=NOW + dt.timedelta(days=4000))

    assert user.platform_role == PlatformRole.AUDITOR


@pytest.mark.integration
async def test_a_new_grant_replaces_an_expired_one(db_session: AsyncSession) -> None:
    """The unique index only counts unrevoked rows, so an expired-but-unswept grant
    still occupies the slot. Granting has to supersede it rather than collide."""
    user = await make_user(db_session)
    await grant_role(
        db_session,
        user,
        role=PlatformRole.ADMIN,
        granter=ADMIN,
        now=NOW,
        expires_at=NOW + dt.timedelta(hours=1),
    )

    after = NOW + dt.timedelta(days=2)
    fresh = await grant_role(db_session, user, role=PlatformRole.HELPDESK, granter=ADMIN, now=after)

    assert fresh.revoked_at is None
    assert user.platform_role == PlatformRole.HELPDESK
    assert len(await history(db_session, user.id)) == 2


# ------------------------------------------------------------ the safety net


@pytest.mark.integration
async def test_nothing_in_the_database_has_drifted(db_session: AsyncSession) -> None:
    """The check that makes the cache design defensible rather than hopeful.

    Anything here means either something wrote platform_role without going through
    iam/access/roles.py, or the migration backfill missed somebody.
    """
    drift = await find_drift(db_session, now=dt.datetime.now(dt.UTC))

    assert drift == [], f"cached roles disagree with grants: {drift}"


@pytest.mark.integration
async def test_the_drift_check_actually_catches_drift(db_session: AsyncSession) -> None:
    """A safety net that always reports nothing is worse than none, so this
    breaks the cache and checks that it gets caught."""
    user = await make_user(db_session)
    user.platform_role = PlatformRole.ADMIN
    await db_session.flush()

    drift = await find_drift(db_session, now=NOW)

    mine = [row for row in drift if row.user_id == user.id]
    assert len(mine) == 1
    assert mine[0].cached == PlatformRole.ADMIN
    assert mine[0].actual == PlatformRole.EMPLOYEE
