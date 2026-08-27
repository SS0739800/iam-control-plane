"""Granting, revoking and working out someone's console role.

Grants are the truth. ``User.platform_role`` is a cache of them.

That needs justifying, because a cache that can disagree with its source is a bug
waiting to happen. The reason is that every single authenticated request needs to
know what the caller is allowed to do. Deriving that from the grants table means a
join on every request, forever, to answer a question that changes maybe twice a
year per person. So the answer is written onto the user's row, and this module is
the only thing allowed to write it.

What keeps the cache honest:

- Nothing else sets ``platform_role``. Every path that changes a grant goes
  through ``grant_role`` or ``revoke_role``, and both finish by recomputing.
- The database allows only one unrevoked grant per person, so "recompute" is a
  single-row lookup with no ordering question to get wrong.
- Expiry is the one thing that changes the answer without anybody writing
  anything, so ``expire_due_grants`` exists and is called before a privileged
  request is trusted.
- ``find_drift`` recomputes everybody and reports disagreements. There is a test
  that runs it and expects nothing.

Roles do not stack. One person, one role, and granting a second supersedes the
first. Additive roles would mean helpdesk plus auditor quietly adding up to
something close to admin that nobody granted, and the point of this table is that
every power somebody has traces back to a decision.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.access import RevokedGrantReason, RoleGrant
from iam.models.enums import GrantSource, PlatformRole
from iam.models.user import User

logger = logging.getLogger(__name__)


class RoleGrantRefused(Exception):
    """The grant doesn't make sense, and the message says why."""


@dataclasses.dataclass(frozen=True, slots=True)
class Granter:
    """Whoever is doing the granting.

    Carries the label as well as the id so the grant can record a name that
    survives the granter's own row being deleted. A system-initiated grant — a
    rule firing, an approved request — has no id and says so in the label.
    """

    user_id: uuid.UUID | None
    label: str


async def count_live_admins(db: AsyncSession, *, now: dt.datetime) -> int:
    """How many people can currently grant anything.

    Counted from the grants rather than the cached column, because this number is the
    thing standing between us and an unrecoverable system, and it should not depend on
    a cache being right.

    Only counts people who are still active: a deactivated admin cannot sign in, so
    they are no help at all when the last other admin is being removed. That clause is
    also why deactivating somebody has to ask this question — switching off the last
    admin empties the set just as surely as revoking their grant.
    """
    return (
        await db.scalar(
            select(func.count())
            .select_from(RoleGrant)
            .join(User, User.id == RoleGrant.user_id)
            .where(
                RoleGrant.role == PlatformRole.ADMIN,
                RoleGrant.revoked_at.is_(None),
                (RoleGrant.expires_at.is_(None)) | (RoleGrant.expires_at > now),
                User.active.is_(True),
            )
        )
        or 0
    )


async def live_grant(db: AsyncSession, user_id: uuid.UUID, *, now: dt.datetime) -> RoleGrant | None:
    """The grant currently giving somebody their role, if there is one.

    Returns nothing for a grant that has expired but not yet been swept, so
    callers get the right answer even when the sweep is behind.
    """
    found = await db.scalar(
        select(RoleGrant).where(RoleGrant.user_id == user_id, RoleGrant.revoked_at.is_(None))
    )
    if found is None or not found.is_live(now=now):
        return None
    return found


async def effective_role(db: AsyncSession, user_id: uuid.UUID, *, now: dt.datetime) -> PlatformRole:
    """What this person's role actually is, worked out from their grants.

    The slow, correct answer. ``User.platform_role`` is the fast copy of it.
    """
    grant = await live_grant(db, user_id, now=now)
    return grant.role if grant else PlatformRole.EMPLOYEE


async def _recompute(db: AsyncSession, user: User, *, now: dt.datetime) -> PlatformRole:
    """Rewrite the cached role from the grants. The only writer of that column."""
    role = await effective_role(db, user.id, now=now)
    if user.platform_role != role:
        logger.info(
            "access.role_changed",
            extra={"user": user.user_name, "from": str(user.platform_role), "to": str(role)},
        )
        user.platform_role = role
    return role


async def grant_role(
    db: AsyncSession,
    user: User,
    *,
    role: PlatformRole,
    granter: Granter,
    now: dt.datetime,
    reason: str | None = None,
    expires_at: dt.datetime | None = None,
    source: GrantSource = GrantSource.DIRECT,
) -> RoleGrant:
    """Give somebody a console role, replacing whatever they had.

    Returns the new grant. The previous one, if any, comes back revoked as
    superseded rather than deleted, so the history reads as a sequence of
    decisions instead of a single mutable fact.

    Raises:
        RoleGrantRefused: For 'employee', which is the absence of a grant rather
            than a grant; for an expiry date in the past; or for somebody who has
            been deactivated.
    """
    if role == PlatformRole.EMPLOYEE:
        raise RoleGrantRefused(
            "Employee is what somebody is when nothing has been granted to them. "
            "Revoke their current role instead of granting this one."
        )

    if expires_at is not None and expires_at <= now:
        raise RoleGrantRefused(
            "That expiry date has already passed, so the grant would do nothing."
        )

    if not user.active:
        # Granting access to somebody who has left is either a mistake or the
        # first half of an attack. Reactivate them first, deliberately.
        raise RoleGrantRefused(
            f"{user.user_name} is deactivated. Reactivate them before granting access."
        )

    existing = await db.scalar(
        select(RoleGrant).where(RoleGrant.user_id == user.id, RoleGrant.revoked_at.is_(None))
    )

    if existing is not None:
        # Same role, still live, no end date change: nothing to do. Worth catching
        # because a rule re-firing shouldn't fill the history with identical rows.
        if (
            existing.role == role
            and existing.expires_at == expires_at
            and existing.is_live(now=now)
        ):
            return existing

        existing.revoked_at = now
        existing.revoked_by_id = granter.user_id
        existing.revoked_by_label = granter.label
        existing.revoked_reason = RevokedGrantReason.SUPERSEDED
        # Flushed before the insert so the one-live-grant index sees the revoke
        # first. Without this the two rows collide inside the same statement batch.
        await db.flush()

    created = RoleGrant(
        user_id=user.id,
        role=role,
        source=source,
        reason=reason,
        granted_by_id=granter.user_id,
        granted_by_label=granter.label,
        expires_at=expires_at,
    )
    db.add(created)
    await db.flush()

    await _recompute(db, user, now=now)

    logger.info(
        "access.role_granted",
        extra={
            "user": user.user_name,
            "role": str(role),
            "by": granter.label,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "source": str(source),
        },
    )
    return created


async def revoke_role(
    db: AsyncSession,
    user: User,
    *,
    granter: Granter,
    now: dt.datetime,
    reason: str = RevokedGrantReason.REVOKED,
) -> RoleGrant | None:
    """Take somebody's role away, putting them back to employee.

    Returns the grant that was revoked, or nothing if they didn't have one.
    Revoking twice is not an error: the end state is what was asked for.
    """
    existing = await db.scalar(
        select(RoleGrant).where(RoleGrant.user_id == user.id, RoleGrant.revoked_at.is_(None))
    )

    if existing is None:
        # Still recompute. If the cache says admin and there is no grant, this is
        # the moment that gets fixed rather than a permanent lie.
        await _recompute(db, user, now=now)
        return None

    existing.revoked_at = now
    existing.revoked_by_id = granter.user_id
    existing.revoked_by_label = granter.label
    existing.revoked_reason = reason
    await db.flush()

    await _recompute(db, user, now=now)

    logger.info(
        "access.role_revoked",
        extra={
            "user": user.user_name,
            "role": str(existing.role),
            "by": granter.label,
            "reason": reason,
        },
    )
    return existing


async def expire_due_grants(db: AsyncSession, *, now: dt.datetime) -> int:
    """Revoke every grant whose end date has passed, and fix the cached roles.

    Expiry is the one way somebody's role changes with nobody writing anything, so
    it needs sweeping rather than reacting. Called from a scheduled command, and
    also just before a privileged request is trusted — see iam/security/actor.py,
    because "their admin access expired an hour ago but the sweep runs at
    midnight" is not an acceptable window.

    Returns how many were ended.
    """
    due = (
        await db.scalars(
            select(RoleGrant).where(
                RoleGrant.revoked_at.is_(None),
                RoleGrant.expires_at.is_not(None),
                RoleGrant.expires_at <= now,
            )
        )
    ).all()

    if not due:
        return 0

    await db.execute(
        update(RoleGrant)
        .where(RoleGrant.id.in_([grant.id for grant in due]))
        .values(
            revoked_at=now,
            revoked_reason=RevokedGrantReason.EXPIRED,
            revoked_by_label="the clock",
        )
    )

    # Reset the cached role for everybody affected. Done as one statement rather
    # than a loop, because the sweep can touch many people at once and each one
    # would otherwise be a separate round trip.
    await db.execute(
        update(User)
        .where(User.id.in_([grant.user_id for grant in due]))
        .values(platform_role=PlatformRole.EMPLOYEE)
    )

    logger.info(
        "access.grants_expired",
        extra={"count": len(due), "users": [str(grant.user_id) for grant in due]},
    )
    return len(due)


async def expire_due_grants_for(db: AsyncSession, user: User, *, now: dt.datetime) -> bool:
    """The same sweep, for one person, on the path of their own request.

    Cheaper than the full sweep and safe to call often: one indexed lookup, and it
    only runs for people the cache says are privileged, who are few.

    Returns whether anything changed.
    """
    existing = await db.scalar(
        select(RoleGrant).where(
            RoleGrant.user_id == user.id,
            RoleGrant.revoked_at.is_(None),
            RoleGrant.expires_at.is_not(None),
            RoleGrant.expires_at <= now,
        )
    )
    if existing is None:
        return False

    existing.revoked_at = now
    existing.revoked_reason = RevokedGrantReason.EXPIRED
    existing.revoked_by_label = "the clock"
    await db.flush()

    await _recompute(db, user, now=now)
    return True


async def revoke_for_leaver(
    db: AsyncSession, user: User, *, granter: Granter, now: dt.datetime
) -> RoleGrant | None:
    """Cut somebody's console role because they left.

    Its own function rather than a parameter on revoke_role, so the leaver flow
    reads as one thing and the audit log can say why the access ended.
    """
    return await revoke_role(
        db, user, granter=granter, now=now, reason=RevokedGrantReason.USER_DEACTIVATED
    )


async def history(db: AsyncSession, user_id: uuid.UUID) -> list[RoleGrant]:
    """Every role this person has ever been given, newest first.

    The access review view. Includes revoked and expired grants, because "what did
    they used to be able to do" is most of the question.
    """
    rows = await db.scalars(
        select(RoleGrant)
        .where(RoleGrant.user_id == user_id)
        .order_by(RoleGrant.created_at.desc(), RoleGrant.id.desc())
    )
    return list(rows.all())


@dataclasses.dataclass(frozen=True, slots=True)
class Drift:
    """One person whose cached role disagrees with their grants."""

    user_id: uuid.UUID
    user_name: str
    cached: PlatformRole
    actual: PlatformRole


async def find_drift(db: AsyncSession, *, now: dt.datetime) -> list[Drift]:
    """Recompute everybody and report where the cache is wrong.

    The safety net for the whole design. If this ever returns anything, either
    something wrote ``platform_role`` without going through this module, or the
    expiry sweep has not run. A test calls it and expects an empty list.

    One query for the users and one for the grants, then compared in Python.
    Deliberately not a clever join: this runs rarely, and being obviously correct
    matters more than being fast.
    """
    users = (await db.scalars(select(User))).all()
    grants = (await db.scalars(select(RoleGrant).where(RoleGrant.revoked_at.is_(None)))).all()

    live_by_user = {grant.user_id: grant.role for grant in grants if grant.is_live(now=now)}

    return [
        Drift(
            user_id=user.id,
            user_name=user.user_name,
            cached=user.platform_role,
            actual=live_by_user.get(user.id, PlatformRole.EMPLOYEE),
        )
        for user in users
        if user.platform_role != live_by_user.get(user.id, PlatformRole.EMPLOYEE)
    ]
