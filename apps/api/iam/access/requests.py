"""Asking for access, and deciding on it.

Covers access that doesn't follow from the rules engine — a one-off need with
no attribute behind it.

Rules:
- Nobody can approve their own request (checked here and in the database).
- A decision is final. Approved, denied, and withdrawn all stay that way;
  asking again means raising a new request.
- Approving writes the group membership in the same transaction as the
  decision, so a request is never left "approved" without the access applied.
- A request can carry an expiry, which lands on the membership itself, so
  temporary access actually expires.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import MembershipSource, PlatformRole, RequestState
from iam.models.group import Group, GroupMember
from iam.models.requests import AccessRequest
from iam.models.user import User
from iam.security.permissions import Permission, permissions_for

logger = logging.getLogger(__name__)


class RequestRefused(Exception):
    """The request or decision can't be made, and the message says why."""


@dataclasses.dataclass(frozen=True, slots=True)
class Decider:
    """Whoever is answering. Carries the label so the record survives their row."""

    user_id: uuid.UUID
    label: str


async def approvers(db: AsyncSession) -> list[User]:
    """Everyone who could decide a request: anyone who can change group
    membership by hand. Deactivated people are excluded since they can't
    sign in to answer it.

    This is "every admin", not per-group owners — the group table has no
    owner column yet.
    """
    candidates = (await db.scalars(select(User).where(User.active))).all()
    return [
        person
        for person in candidates
        if Permission.GROUPS_WRITE in permissions_for(person.platform_role)
    ]


async def open_request_for(
    db: AsyncSession, user_id: uuid.UUID, group_id: uuid.UUID
) -> AccessRequest | None:
    """The pending request this person already has for this group, if any."""
    found: AccessRequest | None = await db.scalar(
        select(AccessRequest).where(
            AccessRequest.requester_id == user_id,
            AccessRequest.group_id == group_id,
            AccessRequest.state == RequestState.PENDING,
        )
    )
    return found


async def raise_request(
    db: AsyncSession,
    *,
    requester: User,
    group: Group,
    reason: str,
    now: dt.datetime,
) -> AccessRequest:
    """Ask to be put in a group.

    Raises:
        RequestRefused: They already have it, they already asked, the reason is
            empty, or they are deactivated.
    """
    if not requester.active:
        raise RequestRefused("A deactivated account can't request access.")

    if not reason.strip():
        # Required — without a reason, an approver has nothing to weigh.
        raise RequestRefused("Say why the access is needed. An approver needs something to weigh.")

    already_in = await db.scalar(
        select(GroupMember).where(
            GroupMember.user_id == requester.id, GroupMember.group_id == group.id
        )
    )
    if already_in is not None:
        raise RequestRefused(f"{requester.display_name} is already in {group.name}.")

    existing = await open_request_for(db, requester.id, group.id)
    if existing is not None:
        raise RequestRefused(
            f"There is already an open request for {group.name}, raised "
            f"{existing.created_at:%d %b %Y}. It has to be decided first."
        )

    request = AccessRequest(
        requester_id=requester.id,
        requester_label=f"{requester.display_name} <{requester.user_name}>",
        group_id=group.id,
        group_label=group.name,
        reason=reason.strip(),
        state=RequestState.PENDING,
    )
    db.add(request)
    await db.flush()

    logger.info(
        "requests.raised",
        extra={
            "request_id": str(request.id),
            "requester": requester.user_name,
            "group": group.name,
        },
    )
    return request


def _guard_decision(request: AccessRequest, decider: Decider) -> None:
    """The two checks every decision has to pass.

    Raises:
        RequestRefused: The request is already decided, or the decider is the
            person who asked.
    """
    if not request.is_open:
        raise RequestRefused(
            f"That request was already {request.state} on "
            f"{request.decided_at:%d %b %Y}. Raise a new one instead of reopening it."
            if request.decided_at
            else f"That request is already {request.state}."
        )

    if request.requester_id == decider.user_id:
        raise RequestRefused(
            "You can't decide your own access request. Somebody else has to look at it."
        )


async def approve(
    db: AsyncSession,
    request: AccessRequest,
    *,
    decider: Decider,
    now: dt.datetime,
    note: str | None = None,
    expires_at: dt.datetime | None = None,
) -> GroupMember:
    """Approve a request and add them to the group, in one transaction, so a
    decision is never recorded without the access being applied.

    Raises:
        RequestRefused: Already decided, self-approval, an expiry in the past, or
            the requester has since been deactivated.
    """
    _guard_decision(request, decider)

    if expires_at is not None and expires_at <= now:
        raise RequestRefused("That expiry has already passed, so the access would never apply.")

    requester = await db.get(User, request.requester_id)
    if requester is None or not requester.active:
        # Block approval instead of granting then immediately revoking if the
        # requester was deactivated after asking.
        raise RequestRefused(
            "The person who asked has been deactivated, so this can't be approved. "
            "Cancel it instead."
        )

    request.state = RequestState.APPROVED
    request.decided_by_id = decider.user_id
    request.decided_by_label = decider.label
    request.decided_at = now
    request.decision_note = note
    request.expires_at = expires_at

    membership = GroupMember(
        group_id=request.group_id,
        user_id=request.requester_id,
        # REQUEST, not MANUAL, so a review can tell this came from an
        # approved request rather than a direct add.
        source=MembershipSource.REQUEST,
    )
    db.add(membership)
    await db.flush()

    logger.info(
        "requests.approved",
        extra={
            "request_id": str(request.id),
            "requester": request.requester_label,
            "group": request.group_label,
            "by": decider.label,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    return membership


async def deny(
    db: AsyncSession,
    request: AccessRequest,
    *,
    decider: Decider,
    now: dt.datetime,
    note: str | None = None,
) -> AccessRequest:
    """Turn a request down. Kept, not deleted, so the history of past
    refusals is still there later.

    Raises:
        RequestRefused: Already decided, or self-denial (same rule as approval).
    """
    _guard_decision(request, decider)

    request.state = RequestState.DENIED
    request.decided_by_id = decider.user_id
    request.decided_by_label = decider.label
    request.decided_at = now
    request.decision_note = note
    await db.flush()

    logger.info(
        "requests.denied",
        extra={
            "request_id": str(request.id),
            "requester": request.requester_label,
            "group": request.group_label,
            "by": decider.label,
        },
    )
    return request


async def withdraw(
    db: AsyncSession, request: AccessRequest, *, by: Decider, now: dt.datetime
) -> AccessRequest:
    """The requester changing their mind. Its own state, separate from a
    denial, since "they withdrew it" and "we turned them down" are different
    answers.

    Raises:
        RequestRefused: Already decided, or somebody else trying to withdraw it.
    """
    if not request.is_open:
        raise RequestRefused(f"That request is already {request.state}.")

    if request.requester_id != by.user_id:
        raise RequestRefused("Only the person who asked can withdraw a request. Deny it instead.")

    request.state = RequestState.WITHDRAWN
    # Recording the requester as decider is fine here — the DB's
    # approver_is_not_the_requester check only applies to approved/denied,
    # since that rule is about who may decide, not who may withdraw.
    request.decided_by_id = by.user_id
    request.decided_by_label = by.label
    request.decided_at = now
    await db.flush()

    logger.info("requests.withdrawn", extra={"request_id": str(request.id)})
    return request


async def cancel(
    db: AsyncSession, request: AccessRequest, *, now: dt.datetime, reason: str
) -> AccessRequest:
    """Close a request that events overtook — usually the requester leaving.
    Not a denial: nobody weighed it and said no, it just stopped being
    relevant.
    """
    if not request.is_open:
        raise RequestRefused(f"That request is already {request.state}.")

    request.state = RequestState.CANCELLED
    request.decided_at = now
    request.decision_note = reason
    await db.flush()

    logger.info("requests.cancelled", extra={"request_id": str(request.id), "reason": reason})
    return request


async def cancel_open_for_leaver(db: AsyncSession, user_id: uuid.UUID, *, now: dt.datetime) -> int:
    """Close anything this person had outstanding, because they left —
    otherwise it sits in the approvers' queue and could get approved after
    they're gone.
    """
    open_requests = (
        await db.scalars(
            select(AccessRequest).where(
                AccessRequest.requester_id == user_id,
                AccessRequest.state == RequestState.PENDING,
            )
        )
    ).all()

    for request in open_requests:
        await cancel(db, request, now=now, reason="The person who asked was deactivated.")

    return len(open_requests)


async def pending(db: AsyncSession, *, limit: int = 100) -> list[AccessRequest]:
    """The approvers' queue, oldest first — the order it should be worked in."""
    rows = await db.scalars(
        select(AccessRequest)
        .where(AccessRequest.state == RequestState.PENDING)
        .order_by(AccessRequest.created_at)
        .limit(limit)
    )
    return list(rows.all())


async def raised_by(db: AsyncSession, user_id: uuid.UUID) -> list[AccessRequest]:
    """Everything one person has ever asked for, newest first."""
    rows = await db.scalars(
        select(AccessRequest)
        .where(AccessRequest.requester_id == user_id)
        .order_by(AccessRequest.created_at.desc())
    )
    return list(rows.all())


def can_decide(role: PlatformRole) -> bool:
    """Whether somebody with this role could decide a request at all."""
    return Permission.GROUPS_WRITE in permissions_for(role)
