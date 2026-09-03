"""Tests for the access review.

Each check gets two tests: it fires when it should, and stays quiet when it
shouldn't — a review that reports things nobody can act on gets ignored.

Provider-owned memberships and seeded data are tested as exclusions too:
the leaver flow always leaves the first alone, and the second isn't real
data.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access.review import run
from iam.models.access import RoleGrant
from iam.models.enums import (
    GrantSource,
    IdentitySource,
    MembershipSource,
    PlatformRole,
    RequestState,
)
from iam.models.group import Group, GroupMember
from iam.models.requests import AccessRequest
from iam.models.user import User

pytestmark = pytest.mark.integration

NOW = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)


async def make_person(db: AsyncSession, *, active: bool = True) -> User:
    suffix = uuid.uuid4().hex[:12]
    person = User(
        user_name=f"review.{suffix}@demo.local",
        email=f"review.{suffix}@demo.local",
        display_name=f"Review Subject {suffix}",
        active=active,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.MANUAL,
    )
    db.add(person)
    await db.flush()
    return person


async def make_group(db: AsyncSession) -> Group:
    group = Group(name=f"review-{uuid.uuid4().hex[:8]}", source=IdentitySource.MANUAL)
    db.add(group)
    await db.flush()
    return group


async def give_role(
    db: AsyncSession,
    person: User,
    role: PlatformRole = PlatformRole.ADMIN,
    *,
    reason: str | None = "Because",
    expires_at: dt.datetime | None = None,
    source: GrantSource = GrantSource.DIRECT,
) -> RoleGrant:
    grant = RoleGrant(
        user_id=person.id,
        role=role,
        source=source,
        reason=reason,
        granted_by_label="a test",
        expires_at=expires_at,
    )
    db.add(grant)
    person.platform_role = role
    await db.flush()
    return grant


async def findings_about(db: AsyncSession, person: User, kind: str) -> list[str]:
    """The concerns raised about one person by one check.

    Filtered to the person the test made, because the test database is shared and a
    review looks at everybody.
    """
    review = await run(db, now=NOW)
    return [
        finding.concern
        for finding in review.findings
        if finding.kind == kind and finding.subject_user_id == person.id
    ]


# ------------------------------------------------------- standing privilege


async def test_a_role_with_no_end_date_is_flagged(db_session: AsyncSession) -> None:
    """The commonest way somebody is still an admin years after the reason expired."""
    person = await make_person(db_session)
    await give_role(db_session, person, PlatformRole.ADMIN, expires_at=None)

    assert await findings_about(db_session, person, "standing_privilege")


async def test_a_role_with_an_end_date_is_not_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    await give_role(db_session, person, PlatformRole.ADMIN, expires_at=NOW + dt.timedelta(days=30))

    assert await findings_about(db_session, person, "standing_privilege") == []


async def test_standing_admin_outranks_standing_auditor(db_session: AsyncSession) -> None:
    """A review that treats them alike buries the one that matters."""
    admin = await make_person(db_session)
    auditor = await make_person(db_session)
    await give_role(db_session, admin, PlatformRole.ADMIN)
    await give_role(db_session, auditor, PlatformRole.AUDITOR)

    review = await run(db_session, now=NOW)
    by_id = {
        finding.subject_user_id: finding.severity
        for finding in review.findings
        if finding.kind == "standing_privilege"
    }

    assert by_id[admin.id] == "high"
    assert by_id[auditor.id] == "medium"


# ---------------------------------------------------------- unexplained roles


async def test_a_migrated_grant_is_flagged(db_session: AsyncSession) -> None:
    """Nobody recorded who decided these. Clearing them is what a review is for."""
    person = await make_person(db_session)
    await give_role(db_session, person, source=GrantSource.MIGRATED, reason=None)

    assert await findings_about(db_session, person, "unexplained_role")


async def test_a_deliberate_grant_is_not_called_unexplained(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    await give_role(db_session, person, source=GrantSource.DIRECT, reason="For the migration")

    assert await findings_about(db_session, person, "unexplained_role") == []


# ------------------------------------------------------------ missing reasons


async def test_a_grant_with_no_reason_is_flagged(db_session: AsyncSession) -> None:
    """Why is the only part of a review that can't be reconstructed later."""
    person = await make_person(db_session)
    await give_role(db_session, person, reason=None)

    assert await findings_about(db_session, person, "no_reason_recorded")


async def test_whitespace_does_not_count_as_a_reason(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    await give_role(db_session, person, reason="   ")

    assert await findings_about(db_session, person, "no_reason_recorded")


async def test_a_grant_with_a_reason_is_not_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    await give_role(db_session, person, reason="Covering the migration weekend")

    assert await findings_about(db_session, person, "no_reason_recorded") == []


# --------------------------------------------------------------- leavers


async def test_a_leaver_still_holding_a_role_is_flagged(db_session: AsyncSession) -> None:
    """Means the leaver flow didn't run, or somebody was switched off in the database."""
    person = await make_person(db_session, active=False)
    await give_role(db_session, person)

    concerns = await findings_about(db_session, person, "leaver_keeps_role")

    assert concerns
    assert "deactivated" in concerns[0]


async def test_a_leaver_in_a_group_we_granted_is_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session, active=False)
    group = await make_group(db_session)
    db_session.add(
        GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.MANUAL)
    )
    await db_session.flush()

    assert await findings_about(db_session, person, "leaver_keeps_groups")


async def test_a_leaver_in_a_provider_owned_group_is_not_flagged(
    db_session: AsyncSession,
) -> None:
    """The leaver flow always leaves those alone, so flagging them would
    just report normal behavior as a problem."""
    person = await make_person(db_session, active=False)
    group = await make_group(db_session)
    db_session.add(GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.SCIM))
    await db_session.flush()

    assert await findings_about(db_session, person, "leaver_keeps_groups") == []


async def test_seeded_membership_is_not_flagged(db_session: AsyncSession) -> None:
    """Demo data is not a finding."""
    person = await make_person(db_session, active=False)
    group = await make_group(db_session)
    db_session.add(GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.SEED))
    await db_session.flush()

    assert await findings_about(db_session, person, "leaver_keeps_groups") == []


# ------------------------------------------------------------ expiry sweep


async def test_a_lapsed_grant_nothing_revoked_is_flagged(db_session: AsyncSession) -> None:
    """Harmless — expiry is checked per request — but it means the sweep is behind."""
    person = await make_person(db_session)
    await give_role(db_session, person, expires_at=NOW - dt.timedelta(days=1))

    concerns = await findings_about(db_session, person, "lapsed_not_swept")

    assert concerns
    assert "sweep" in concerns[0]


async def test_a_grant_that_has_not_lapsed_is_not_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    await give_role(db_session, person, expires_at=NOW + dt.timedelta(days=1))

    assert await findings_about(db_session, person, "lapsed_not_swept") == []


# -------------------------------------------------------- unanswered requests


async def test_an_old_pending_request_is_flagged(db_session: AsyncSession) -> None:
    """Somebody is waiting, and a queue nobody works teaches people to route round it."""
    person = await make_person(db_session)
    group = await make_group(db_session)
    db_session.add(
        AccessRequest(
            requester_id=person.id,
            requester_label=person.display_name,
            group_id=group.id,
            group_label=group.name,
            reason="Still waiting",
            state=RequestState.PENDING,
            created_at=NOW - dt.timedelta(days=30),
        )
    )
    await db_session.flush()

    assert await findings_about(db_session, person, "unanswered_request")


async def test_a_fresh_request_is_not_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    group = await make_group(db_session)
    db_session.add(
        AccessRequest(
            requester_id=person.id,
            requester_label=person.display_name,
            group_id=group.id,
            group_label=group.name,
            reason="Asked this morning",
            state=RequestState.PENDING,
            created_at=NOW - dt.timedelta(hours=2),
        )
    )
    await db_session.flush()

    assert await findings_about(db_session, person, "unanswered_request") == []


# ------------------------------------------------------------ empty groups


async def test_an_empty_group_is_flagged(db_session: AsyncSession) -> None:
    """A door with nobody behind it. Whoever is added first inherits whatever it
    grants, and nobody remembers deciding that."""
    group = await make_group(db_session)

    review = await run(db_session, now=NOW)
    subjects = [f.subject for f in review.findings if f.kind == "empty_group"]

    assert group.name in subjects


async def test_a_group_with_members_is_not_flagged(db_session: AsyncSession) -> None:
    person = await make_person(db_session)
    group = await make_group(db_session)
    db_session.add(
        GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.MANUAL)
    )
    await db_session.flush()

    review = await run(db_session, now=NOW)
    subjects = [f.subject for f in review.findings if f.kind == "empty_group"]

    assert group.name not in subjects


# ----------------------------------------------------------------- the shape


async def test_findings_come_back_worst_first(db_session: AsyncSession) -> None:
    """Somebody working through this from the top should hit the real problems first."""
    review = await run(db_session, now=NOW)
    order = {"high": 0, "medium": 1, "low": 2}

    ranks = [order[finding.severity] for finding in review.findings]

    assert ranks == sorted(ranks)


async def test_every_finding_says_what_to_do_about_it(db_session: AsyncSession) -> None:
    """A finding with no available action is a complaint, and after the second
    review nobody reads those."""
    person = await make_person(db_session)
    await give_role(db_session, person, reason=None)

    review = await run(db_session, now=NOW)

    assert review.findings
    for finding in review.findings:
        assert finding.suggested_action.strip(), f"{finding.kind} has no suggested action"
        assert finding.concern.strip(), f"{finding.kind} does not say what the concern is"
