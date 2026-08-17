"""Asking for access, and deciding.

The rules engine covers access that follows from who somebody is. This covers the
rest: the person who needs the finance system for one quarter and has no attribute
that says so.

Approving is the interesting part, and what makes it worth having is what it
refuses.

**Nobody approves their own request.** Checked here and constrained in the
database. An approval step you can perform on yourself is a form somebody fills in
twice, and every other control in this system assumes it means something.

**A decision is final.** Approved, denied and withdrawn all stay that way. Asking
again is a new request, which is honest about there having been two, rather than a
reopened one that makes "who approved this" ambiguous.

**Approving grants the access.** The point of failure in a workflow like this is
an approval that records a decision and doesn't act on it, leaving somebody
waiting for access they were told they had. So the membership is written in the
same transaction as the decision.

Temporary access
----------------

A request can carry an expiry, and it lands on the membership rather than being
forgotten. "Approved until the end of the quarter" is the common real answer to an
access request, and a system that can only grant forever turns every temporary
need into permanent access.
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
    """Everybody who could decide a request.

    Anyone who can change group membership by hand, since approving is exactly
    that with a paper trail. Deactivated people are excluded: they can't sign in,
    so listing them as approvers would mean emailing a request to somebody who
    cannot answer it.

    Per-group owners would be better than "every admin", and are the obvious next
    step — the group table has no owner column yet, and inventing one here would be
    a bigger change than this module.
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
        # Required, and not just for tidiness. An approver with no reason in front
        # of them is rubber-stamping, which is the failure this whole flow is meant
        # to avoid.
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
        # The rule that makes the approval step mean anything.
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
    """Approve a request and put them in the group.

    Both, in one transaction. An approval that records a decision without granting
    the access leaves somebody waiting for something they were told they had, which
    is the worst outcome available here.

    Raises:
        RequestRefused: Already decided, self-approval, an expiry in the past, or
            the requester has since been deactivated.
    """
    _guard_decision(request, decider)

    if expires_at is not None and expires_at <= now:
        raise RequestRefused("That expiry has already passed, so the access would never apply.")

    requester = await db.get(User, request.requester_id)
    if requester is None or not requester.active:
        # Approving access for somebody who has left is how a leaver quietly keeps
        # a foothold. Refused rather than granted-then-revoked.
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
        # Not MANUAL. A review asking "why is this person in here" should get
        # "somebody approved a request", which is a different answer from "somebody
        # added them", and the request id is findable from the audit entry.
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
    """Turn a request down.

    Kept, not deleted. "We asked twice and were refused twice" is a fact somebody
    eventually needs, and it only exists if denied requests survive.

    Raises:
        RequestRefused: Already decided, or self-denial — which is odd but still
            somebody deciding their own request, and the rule holds either way.
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
    """The requester changing their mind.

    Its own state rather than a denial, because who closed it matters: "they
    withdrew it" and "we turned them down" are different answers to the same
    question.

    Raises:
        RequestRefused: Already decided, or somebody else trying to withdraw it.
    """
    if not request.is_open:
        raise RequestRefused(f"That request is already {request.state}.")

    if request.requester_id != by.user_id:
        raise RequestRefused("Only the person who asked can withdraw a request. Deny it instead.")

    request.state = RequestState.WITHDRAWN
    # The requester is the author here, and that is recorded rather than left
    # blank. The database's approver_is_not_the_requester check is scoped to
    # approved and denied for exactly this reason: the rule is about who may
    # decide, not who may close their own request.
    request.decided_by_id = by.user_id
    request.decided_by_label = by.label
    request.decided_at = now
    await db.flush()

    logger.info("requests.withdrawn", extra={"request_id": str(request.id)})
    return request


async def cancel(
    db: AsyncSession, request: AccessRequest, *, now: dt.datetime, reason: str
) -> AccessRequest:
    """Close a request that events have overtaken — usually the requester leaving.

    Not a denial. Nobody weighed it and decided no; it simply stopped being a
    question, and recording that as a refusal would misrepresent what happened.
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
    """Close anything this person had outstanding, because they left.

    Otherwise their requests sit in the approvers' queue forever, and the obvious
    failure is somebody approving one of them months later without noticing the
    requester is gone.
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
