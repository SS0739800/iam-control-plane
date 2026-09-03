"""Someone left. Take everything away.

Every path that can mean "they left" — SCIM sending ``active: false``, a
DELETE on the SCIM endpoint, or the console — calls this one function, so the
behavior is the same no matter how it was triggered.

What gets removed:
- Every session, not just the browser they're currently using.
- Their console role (revoked with a reason, so a review can tell "we took
  it away" from "it expired").
- App access assigned to them directly.

Group membership is left alone. An inactive user can't authenticate, so
membership grants them nothing anyway, and most groups here are owned by the
provider — deleting membership rows would just get overwritten on the next
sync. Their membership at the time they left is recorded in the audit entry
instead.

Reactivating someone restores no access. They get their account back and
nothing else; every grant has to be made again.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access.requests import cancel_open_for_leaver
from iam.access.roles import Granter, revoke_for_leaver
from iam.models.application import AppAssignment, Application
from iam.models.enums import PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.user import User
from iam.saml.sessions import RevokedReason, revoke_all_for_user

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class RemovedAccess:
    """What cutting somebody off did, so the caller can write one audit entry
    instead of several separate ones.
    """

    sessions_ended: int
    role_revoked: PlatformRole | None
    apps_removed: tuple[str, ...]
    groups_at_departure: tuple[str, ...]
    requests_cancelled: int = 0

    @property
    def anything_happened(self) -> bool:
        return bool(
            self.sessions_ended
            or self.role_revoked is not None
            or self.apps_removed
            or self.requests_cancelled
        )

    def as_audit_detail(self) -> dict[str, object]:
        return {
            "sessions_ended": self.sessions_ended,
            "role_revoked": str(self.role_revoked) if self.role_revoked else None,
            "apps_removed": list(self.apps_removed),
            # Recorded, not removed — see the module docstring for why.
            "groups_at_departure": list(self.groups_at_departure),
            "requests_cancelled": self.requests_cancelled,
        }


async def _direct_app_access(db: AsyncSession, user_id: uuid.UUID) -> list[tuple[str, str | None]]:
    """Apps assigned to this person directly, with the role each gives.

    Only direct assignments — access via a group belongs to the group, and
    removing it would take it from everyone in it.
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
    """Remove everything this person has access to, because they left.

    Does not set ``active`` — the caller owns that flag (SCIM sets it from the
    document it received, the console sets it from the form). This only does
    the "take their access away" part.

    Safe to call twice: the second call finds sessions already revoked, the
    role already gone, and assignments already deleted, so it reports nothing
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

    # Cancel anything still pending, otherwise it sits in an approver's queue
    # and could get approved after the requester is already gone.
    cancelled = await cancel_open_for_leaver(db, user.id, now=now)

    removed = RemovedAccess(
        sessions_ended=sessions_ended,
        role_revoked=revoked.role if revoked else None,
        apps_removed=tuple(f"{name} ({role})" if role else name for name, role in apps),
        groups_at_departure=tuple(groups),
        requests_cancelled=cancelled,
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
