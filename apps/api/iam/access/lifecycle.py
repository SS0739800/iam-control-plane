"""Someone left. Take everything away.

This is the moment the whole project is built to get right. Every design decision
before it was made so this could work: sessions are rows so they can be deleted,
roles are grants so they can be revoked, the audit log is append-only so the
record survives.

Setting a flag and leaving somebody signed in for another eight hours is the
failure this exists to prevent. So one function does all of it, and everything
that can mean "they left" calls that one function — the SCIM provider sending
``active: false``, a DELETE on the SCIM endpoint, and the console.

What gets taken away
--------------------

**Sessions.** Every one, not just the browser they happen to be using.

**Their console role.** Revoked with a reason saying they left, so a review can
tell "we took it away" apart from "it ran out".

**Direct application access.** Access assigned to them personally goes.

**Group membership stays.** Two reasons, and this is the one to argue with if you
disagree. First, an inactive person can't authenticate, so membership grants them
nothing in practice. Second, most groups here are owned by the provider, and
deleting rows it believes in means fighting the next sync — it would put them
straight back, and we would take them away again, forever. What their membership
was at the moment they left is in the audit entry.

Nothing comes back on its own
-----------------------------

Reactivating somebody restores no access. They get their account and nothing
else, and every grant has to be made again deliberately. A rehire who silently
regains everything they had two years ago is how people end up with access nobody
would approve today.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access.roles import Granter, revoke_for_leaver
from iam.models.application import AppAssignment, Application
from iam.models.enums import PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.user import User
from iam.saml.sessions import RevokedReason, revoke_all_for_user

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class RemovedAccess:
    """What cutting somebody off actually did.

    Returned so the caller can write one audit entry describing the whole thing,
    rather than four entries nobody can line up afterwards. It is also what makes
    the removal reviewable: "lost Salesforce (Sales Rep)" is a sentence, and
    "app_assignments: 1" is not.
    """

    sessions_ended: int
    role_revoked: PlatformRole | None
    apps_removed: tuple[str, ...]
    groups_at_departure: tuple[str, ...]

    @property
    def anything_happened(self) -> bool:
        return bool(self.sessions_ended or self.role_revoked is not None or self.apps_removed)

    def as_audit_detail(self) -> dict[str, object]:
        return {
            "sessions_ended": self.sessions_ended,
            "role_revoked": str(self.role_revoked) if self.role_revoked else None,
            "apps_removed": list(self.apps_removed),
            # Recorded rather than removed. See the module docstring on why group
            # membership is left alone.
            "groups_at_departure": list(self.groups_at_departure),
        }


async def _direct_app_access(db: AsyncSession, user_id: uuid.UUID) -> list[tuple[str, str | None]]:
    """Applications assigned to this person directly, with the role each gives.

    Only the direct ones. Access that comes through a group is not theirs to lose
    — it belongs to the group, and removing it would take it from everybody.
    """
    rows = await db.execute(
        select(Application.name, AppAssignment.role)
        .join(AppAssignment, AppAssignment.application_id == Application.id)
        .where(AppAssignment.user_id == user_id)
        .order_by(Application.name)
    )
    return [(name, role) for name, role in rows.all()]


async def _group_names(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    rows = await db.scalars(
        select(Group.name)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .where(GroupMember.user_id == user_id)
        .order_by(Group.name)
    )
    return list(rows.all())


async def cut_access(
    db: AsyncSession, user: User, *, by: Granter, now: dt.datetime
) -> RemovedAccess:
    """Remove everything this person has, because they have left.

    Does not set ``active``. The caller owns that flag — SCIM sets it from the
    document it received, the console sets it from the form — and having two
    places write it would mean guessing which won. This function is only the
    "and now take their access away" half, which is the half that used to be
    missing.

    Safe to call twice. Sessions are already revoked, the role is already gone,
    the assignments are already deleted, so the second call reports nothing
    happened and writes nothing.
    """
    apps = await _direct_app_access(db, user.id)
    groups = await _group_names(db, user.id)

    sessions_ended = await revoke_all_for_user(
        db, user.id, reason=RevokedReason.USER_DEACTIVATED, now=now
    )

    revoked = await revoke_for_leaver(db, user, granter=by, now=now)

    if apps:
        await db.execute(delete(AppAssignment).where(AppAssignment.user_id == user.id))

    removed = RemovedAccess(
        sessions_ended=sessions_ended,
        role_revoked=revoked.role if revoked else None,
        apps_removed=tuple(f"{name} ({role})" if role else name for name, role in apps),
        groups_at_departure=tuple(groups),
    )

    if removed.anything_happened:
        logger.info(
            "access.cut_for_leaver",
            extra={
                "user_name": user.user_name,
                "by": by.label,
                **removed.as_audit_detail(),
            },
        )

    return removed
