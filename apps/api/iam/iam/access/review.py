"""What an access review should actually look at.

The obvious version of this screen is a list of who has what. That is a directory
listing, it is already available on the Users page, and nobody finds anything by
reading it — with a thousand people and four thousand memberships, the eye slides
off.

So this looks for the things that warrant a question. Each finding says what it
found, who it is about, and why somebody should care. A review that produces a
short list of specific concerns gets worked through; one that produces a spreadsheet
gets filed.

Every finding here is answerable
--------------------------------

Each one names something a person can do about it: put an end date on it, record a
reason, revoke it, or run the sweep. A finding with no available action is a
complaint, and after the second review nobody reads those.

What is deliberately not flagged
--------------------------------

Seeded demo data, and memberships the provider owns. Both would be noise: the
first is not real, and the second is authentik's business rather than something an
auditor here can act on. Flagging things nobody can fix is how a review screen
teaches people to ignore it.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.access import RoleGrant
from iam.models.enums import GrantSource, MembershipSource, PlatformRole, RequestState
from iam.models.group import Group, GroupMember
from iam.models.requests import AccessRequest
from iam.models.user import User

logger = logging.getLogger(__name__)

Severity = Literal["high", "medium", "low"]
"""How much a finding matters.

high — somebody has access they should not, right now.
medium — the access is probably fine and nobody can prove it, which is the state
    most real findings are in.
low — worth tidying, no immediate consequence.
"""

_ORDER: dict[Severity, int] = {"high": 0, "medium": 1, "low": 2}


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """One thing worth asking about."""

    kind: str
    severity: Severity
    subject: str
    """Who or what it is about, in words."""

    subject_user_id: uuid.UUID | None
    concern: str
    """Why this is a question, in a sentence somebody can act on."""

    suggested_action: str
    since: dt.datetime | None = None


async def standing_privilege(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Console roles with no end date.

    Not wrong — plenty of people genuinely need permanent access — but it is the
    single most common way somebody ends up an admin years after the reason
    expired. An end date turns that into a decision somebody has to make again.
    """
    rows = (
        await db.execute(
            select(RoleGrant, User)
            .join(User, User.id == RoleGrant.user_id)
            .where(
                RoleGrant.revoked_at.is_(None),
                RoleGrant.expires_at.is_(None),
                User.active.is_(True),
            )
            .order_by(RoleGrant.created_at)
        )
    ).all()

    return [
        Finding(
            kind="standing_privilege",
            # Admin with no end date is a different question from auditor with no
            # end date, and a review that treats them alike buries the one that
            # matters.
            severity="high" if grant.role == PlatformRole.ADMIN else "medium",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=(
                f"Has been {grant.role} since {grant.created_at:%d %b %Y} with no end "
                f"date. Nothing will prompt anybody to look at this again."
            ),
            suggested_action="Put an end date on it, or confirm it is meant to be permanent.",
            since=grant.created_at,
        )
        for grant, user in rows
    ]


async def unexplained_roles(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Roles nobody can account for.

    Grants marked 'migrated' predate this table, so who decided them and when was
    never recorded. That is not somebody's fault and it is exactly what a review
    exists to clear: each one needs a person to say "yes, still needed" and become a
    real decision.
    """
    rows = (
        await db.execute(
            select(RoleGrant, User)
            .join(User, User.id == RoleGrant.user_id)
            .where(
                RoleGrant.revoked_at.is_(None),
                RoleGrant.source == GrantSource.MIGRATED,
                User.active.is_(True),
            )
        )
    ).all()

    return [
        Finding(
            kind="unexplained_role",
            severity="medium",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=(
                f"Is {grant.role}, and there is no record of who granted it or why — "
                f"it predates access grants being written down."
            ),
            suggested_action=(
                "Confirm it is still needed and re-grant it with a reason, or revoke it."
            ),
            since=grant.created_at,
        )
        for grant, user in rows
    ]


async def access_without_a_reason(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Live grants with an empty reason field.

    The reason is the part of a review that cannot be reconstructed afterwards.
    Everything else — who, what, when — is in the row; why is only ever there if
    somebody typed it.
    """
    rows = (
        await db.execute(
            select(RoleGrant, User)
            .join(User, User.id == RoleGrant.user_id)
            .where(
                RoleGrant.revoked_at.is_(None),
                RoleGrant.source != GrantSource.MIGRATED,
                (RoleGrant.reason.is_(None)) | (func.trim(RoleGrant.reason) == ""),
                User.active.is_(True),
            )
        )
    ).all()

    return [
        Finding(
            kind="no_reason_recorded",
            severity="low",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=f"Was granted {grant.role} by {grant.granted_by_label} with no reason given.",
            suggested_action=(
                "Ask them why, and record it. Nothing else here can be reconstructed later."
            ),
            since=grant.created_at,
        )
        for grant, user in rows
    ]


async def access_held_by_leavers(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Deactivated people who still hold something.

    They cannot sign in, so this is not an open door — but it is how a group
    listing stops being trustworthy, and it usually means the leaver flow did not
    run or somebody was deactivated straight in the database.

    Provider-owned memberships are excluded. The leaver flow deliberately leaves
    those alone, so flagging them would report our own intended behaviour as a
    problem, every time, forever.
    """
    role_rows = (
        await db.execute(
            select(RoleGrant, User)
            .join(User, User.id == RoleGrant.user_id)
            .where(RoleGrant.revoked_at.is_(None), User.active.is_(False))
        )
    ).all()

    findings = [
        Finding(
            kind="leaver_keeps_role",
            severity="high",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=(
                f"Is deactivated but still holds {grant.role}. The leaver flow should "
                f"have revoked this."
            ),
            suggested_action="Revoke it, and check why the leaver flow did not.",
            since=grant.created_at,
        )
        for grant, user in role_rows
    ]

    membership_rows = (
        await db.execute(
            select(User, func.count(GroupMember.group_id))
            .join(GroupMember, GroupMember.user_id == User.id)
            .where(
                User.active.is_(False),
                GroupMember.source.in_(
                    [MembershipSource.MANUAL, MembershipSource.REQUEST, MembershipSource.RULE]
                ),
            )
            .group_by(User.id)
        )
    ).all()

    findings.extend(
        Finding(
            kind="leaver_keeps_groups",
            severity="medium",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=(
                f"Is deactivated but is still in {count} group"
                f"{'s' if count != 1 else ''} we granted. Group listings will keep "
                f"showing them."
            ),
            suggested_action="Remove them, or re-run the leaver flow for this person.",
        )
        for user, count in membership_rows
    )

    return findings


async def lapsed_but_not_swept(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Grants past their end date that nothing has revoked yet.

    Harmless in itself — the expiry is checked on the request path, so an expired
    admin is not an admin — but it means the sweep is not running, and the sweep is
    what keeps the cached role on the user row honest.
    """
    rows = (
        await db.execute(
            select(RoleGrant, User)
            .join(User, User.id == RoleGrant.user_id)
            .where(
                RoleGrant.revoked_at.is_(None),
                RoleGrant.expires_at.is_not(None),
                RoleGrant.expires_at <= now,
            )
        )
    ).all()

    return [
        Finding(
            kind="lapsed_not_swept",
            severity="low",
            subject=f"{user.display_name} <{user.user_name}>",
            subject_user_id=user.id,
            concern=(
                f"Their {grant.role} ended on {grant.expires_at:%d %b %Y} but the grant "
                f"has not been closed off. They are not privileged — expiry is checked "
                f"on every request — but the expiry sweep is behind."
            ),
            suggested_action="Run the expiry sweep.",
            since=grant.expires_at,
        )
        for grant, user in rows
    ]


async def stale_requests(
    db: AsyncSession, *, now: dt.datetime, older_than_days: int = 14
) -> list[Finding]:
    """Requests nobody has answered.

    Somebody is waiting, and an approval queue that grows without being worked is
    how people learn to route around the process and ask an admin directly.
    """
    cutoff = now - dt.timedelta(days=older_than_days)
    rows = (
        await db.scalars(
            select(AccessRequest).where(
                AccessRequest.state == RequestState.PENDING,
                AccessRequest.created_at <= cutoff,
            )
        )
    ).all()

    return [
        Finding(
            kind="unanswered_request",
            severity="medium",
            subject=request.requester_label,
            subject_user_id=request.requester_id,
            concern=(
                f"Asked for {request.group_label} on {request.created_at:%d %b %Y} and "
                f"has had no answer."
            ),
            suggested_action="Decide it. If it is not going to be approved, deny it and say why.",
            since=request.created_at,
        )
        for request in rows
    ]


async def groups_nobody_is_in(db: AsyncSession, *, now: dt.datetime) -> list[Finding]:
    """Empty groups that still grant application access.

    An empty group is usually harmless clutter. One with an application attached is
    a door with nobody behind it, and the moment somebody is added they get access
    nobody remembers deciding.
    """
    rows = (
        await db.execute(
            select(Group, func.count(GroupMember.user_id))
            .outerjoin(GroupMember, GroupMember.group_id == Group.id)
            .group_by(Group.id)
            .having(func.count(GroupMember.user_id) == 0)
        )
    ).all()

    return [
        Finding(
            kind="empty_group",
            severity="low",
            subject=group.name,
            subject_user_id=None,
            concern="Nobody is in this group. Anybody added to it inherits whatever it grants.",
            suggested_action="Delete it, or write down what it is for.",
        )
        for group, _ in rows
    ]


@dataclasses.dataclass(frozen=True, slots=True)
class Review:
    """Everything one pass over the directory turned up."""

    findings: tuple[Finding, ...]
    checked_at: dt.datetime

    @property
    def by_severity(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def clean(self) -> bool:
        return not self.findings


async def run(db: AsyncSession, *, now: dt.datetime) -> Review:
    """Look for everything, worst first.

    Each check is a separate function and a separate query rather than one clever
    join. They run rarely, and a reviewer who does not believe a finding needs to be
    able to read the one function that produced it.
    """
    collected: list[Finding] = []
    for check in (
        standing_privilege,
        unexplained_roles,
        access_without_a_reason,
        access_held_by_leavers,
        lapsed_but_not_swept,
        stale_requests,
        groups_nobody_is_in,
    ):
        collected.extend(await check(db, now=now))

    collected.sort(key=lambda finding: (_ORDER[finding.severity], finding.kind, finding.subject))

    logger.info(
        "review.completed",
        extra={"findings": len(collected), "kinds": sorted({f.kind for f in collected})},
    )
    return Review(findings=tuple(collected), checked_at=now)
