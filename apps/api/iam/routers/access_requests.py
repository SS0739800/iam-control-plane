"""Raising access requests and deciding them.

Permissions here are a bit different from the rest of this codebase:

Anyone signed in can raise a request — no permission check. An employee
holds no permissions, so a request system they can't use wouldn't be one.
Asking grants nothing; approval does.

Deciding needs groups:write, since approving means putting someone in a
group, with a paper trail.

Reading is split: your own requests are always visible to you. Everyone
else's needs groups:read, since "who's been asking for the finance system"
is review information, not public.

Notifications are sent after the commit, so nobody is emailed about access
that a rolled-back transaction never actually granted. See iam/mail.py.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from iam.access import (
    Decider,
    RequestRefused,
    approve,
    approvers,
    deny,
    pending,
    raise_request,
    raised_by,
    withdraw,
)
from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep, SettingsDep
from iam.mail import Mail, send
from iam.models.enums import ActorType, AuditOutcome, RequestState
from iam.models.group import Group
from iam.models.requests import AccessRequest
from iam.models.user import User
from iam.schemas.requests import AccessRequestCreate, AccessRequestOut, Decision
from iam.security import Actor, CurrentActor, Permission, require
from iam.security.permissions import permissions_for

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/access-requests", tags=["access requests"])


def _out(request: AccessRequest) -> AccessRequestOut:
    return AccessRequestOut(
        id=request.id,
        state=request.state,
        requester_id=request.requester_id,
        requester_label=request.requester_label,
        group_id=request.group_id,
        group_label=request.group_label,
        reason=request.reason,
        decided_by_label=request.decided_by_label,
        decided_at=request.decided_at,
        decision_note=request.decision_note,
        expires_at=request.expires_at,
        created_at=request.created_at,
        is_open=request.is_open,
    )


async def _load(session: SessionDep, request_id: uuid.UUID) -> AccessRequest:
    found = await session.get(AccessRequest, request_id)
    if found is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"No access request with id {request_id}."
        )
    return found


async def _notify_approvers(
    session: SessionDep, settings: SettingsDep, request: AccessRequest
) -> None:
    """Tell whoever can decide that something is waiting."""
    people = await approvers(session)
    body = (
        f"{request.requester_label} has asked to be added to {request.group_label}.\n\n"
        f"Reason given:\n{request.reason}\n\n"
        f"Decide it here: {settings.base_url.rstrip('/')}/access-requests\n"
    )
    await send(
        Mail(
            to=tuple(person.email for person in people if person.email),
            subject=f"Access request: {request.group_label}",
            body=body,
        ),
        settings,
    )


async def _notify_requester(
    session: SessionDep, settings: SettingsDep, request: AccessRequest, outcome: str
) -> None:
    """Tell the person who asked what was decided."""
    requester = await session.get(User, request.requester_id)
    if requester is None or not requester.email:
        return

    note = f"\n\nWhat they said:\n{request.decision_note}" if request.decision_note else ""
    until = f"\n\nThis access ends on {request.expires_at:%d %B %Y}." if request.expires_at else ""
    await send(
        Mail(
            to=(requester.email,),
            subject=f"Access request {outcome}: {request.group_label}",
            body=(
                f"Your request to be added to {request.group_label} was {outcome} "
                f"by {request.decided_by_label}.{note}{until}\n"
            ),
        ),
        settings,
    )


@router.get(
    "/mine",
    response_model=list[AccessRequestOut],
    summary="Everything I have asked for",
)
async def my_requests(session: SessionDep, actor: CurrentActor) -> list[AccessRequestOut]:
    """Your own requests, newest first.

    No permission check. Somebody is always allowed to see what they asked for.
    """
    return [_out(request) for request in await raised_by(session, actor.user_id)]


@router.get(
    "",
    response_model=list[AccessRequestOut],
    summary="The requests waiting to be decided",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def queue(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[AccessRequestOut]:
    """Open requests, oldest first — the order they should be worked in."""
    return [_out(request) for request in await pending(session, limit=limit)]


@router.post(
    "",
    response_model=AccessRequestOut,
    status_code=status.HTTP_201_CREATED,
    summary="Ask for access to a group",
)
async def create_request(
    payload: AccessRequestCreate,
    session: SessionDep,
    settings: SettingsDep,
    actor: CurrentActor,
) -> AccessRequestOut:
    """Raise a request for yourself. No permission required — an employee
    holds no permissions, so asking grants nothing.

    Raises:
        HTTPException: 400 if the request doesn't make sense, 404 for a group that
            isn't there.
    """
    requester = await session.get(User, actor.user_id)
    if requester is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Your user record is missing.")

    group = await session.get(Group, payload.group_id)
    if group is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"No group with id {payload.group_id}."
        )

    now = dt.datetime.now(dt.UTC)
    try:
        request = await raise_request(
            session, requester=requester, group=group, reason=payload.reason, now=now
        )
    except RequestRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await append_event(
        session,
        AuditDraft(
            action="access_request.raised",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_request",
            target_id=str(request.id),
            target_label=request.group_label,
            detail={"group": request.group_label, "reason": request.reason},
        ),
    )
    await session.commit()
    await session.refresh(request)

    # After the commit. Nobody should be emailed about a request that a failed
    # transaction never created.
    await _notify_approvers(session, settings, request)

    return _out(request)


@router.post(
    "/{request_id}/approve",
    response_model=AccessRequestOut,
    summary="Approve a request and grant the access",
)
async def approve_request(
    request_id: uuid.UUID,
    payload: Decision,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> AccessRequestOut:
    """Approve, and put them in the group in the same transaction.

    Raises:
        HTTPException: 400 if it can't be approved — already decided, self-approval,
            an expiry in the past, or the requester has since left.
    """
    request = await _load(session, request_id)
    now = dt.datetime.now(dt.UTC)

    try:
        await approve(
            session,
            request,
            decider=Decider(user_id=actor.user_id, label=actor.audit_label),
            now=now,
            note=payload.note,
            expires_at=payload.expires_at,
        )
    except RequestRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await append_event(
        session,
        AuditDraft(
            action="access_request.approved",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_request",
            target_id=str(request.id),
            target_label=request.group_label,
            detail={
                "requester": request.requester_label,
                "group": request.group_label,
                "note": payload.note,
                "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
            },
        ),
    )
    await session.commit()
    await session.refresh(request)

    await _notify_requester(session, settings, request, "approved")

    return _out(request)


@router.post(
    "/{request_id}/deny",
    response_model=AccessRequestOut,
    summary="Turn a request down",
)
async def deny_request(
    request_id: uuid.UUID,
    payload: Decision,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> AccessRequestOut:
    """Refuse a request, and keep the record of having refused it."""
    request = await _load(session, request_id)

    try:
        await deny(
            session,
            request,
            decider=Decider(user_id=actor.user_id, label=actor.audit_label),
            now=dt.datetime.now(dt.UTC),
            note=payload.note,
        )
    except RequestRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await append_event(
        session,
        AuditDraft(
            action="access_request.denied",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_request",
            target_id=str(request.id),
            target_label=request.group_label,
            detail={
                "requester": request.requester_label,
                "group": request.group_label,
                "note": payload.note,
            },
        ),
    )
    await session.commit()
    await session.refresh(request)

    await _notify_requester(session, settings, request, "denied")

    return _out(request)


@router.post(
    "/{request_id}/withdraw",
    response_model=AccessRequestOut,
    summary="Take back a request you raised",
)
async def withdraw_request(
    request_id: uuid.UUID,
    session: SessionDep,
    actor: CurrentActor,
) -> AccessRequestOut:
    """Withdraw your own request. No permission needed, since it's yours —
    somebody else closing it is a denial and goes through the other endpoint.
    """
    request = await _load(session, request_id)

    try:
        await withdraw(
            session,
            request,
            by=Decider(user_id=actor.user_id, label=actor.audit_label),
            now=dt.datetime.now(dt.UTC),
        )
    except RequestRefused as exc:
        # 403 rather than 400 when it isn't theirs: the request is fine, the caller
        # is the problem.
        code = (
            status.HTTP_403_FORBIDDEN
            if "Only the person who asked" in str(exc)
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(code, detail=str(exc)) from exc

    await append_event(
        session,
        AuditDraft(
            action="access_request.withdrawn",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_request",
            target_id=str(request.id),
            target_label=request.group_label,
            detail={"group": request.group_label},
        ),
    )
    await session.commit()
    await session.refresh(request)

    return _out(request)


@router.get(
    "/{request_id}",
    response_model=AccessRequestOut,
    summary="One request",
)
async def get_request(
    request_id: uuid.UUID, session: SessionDep, actor: CurrentActor
) -> AccessRequestOut:
    """Read one request.

    Yours always; anybody else's needs groups:read. "Who has been asking for the
    finance system" is review information, not public.
    """
    request = await _load(session, request_id)

    somebody_elses = request.requester_id != actor.user_id
    if somebody_elses and Permission.GROUPS_READ not in permissions_for(actor.role):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="That request belongs to somebody else.",
        )

    return _out(request)


@router.get(
    "/group/{group_id}",
    response_model=list[AccessRequestOut],
    summary="Every request ever raised for one group",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def for_group(group_id: uuid.UUID, session: SessionDep) -> list[AccessRequestOut]:
    """The history for a group, decided ones included. Denied requests
    matter here too — "three people asked and were all refused" says
    something the membership list alone doesn't.
    """
    rows = await session.scalars(
        select(AccessRequest)
        .where(AccessRequest.group_id == group_id)
        .order_by(AccessRequest.created_at.desc())
    )
    return [_out(request) for request in rows.all()]


@router.get(
    "/states/summary",
    response_model=dict[str, int],
    summary="How many requests are in each state",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def state_summary(session: SessionDep) -> dict[str, int]:
    """Counts by state, for the console's badge and a quick health read."""
    rows = await session.scalars(select(AccessRequest.state))
    counts = {state.value: 0 for state in RequestState}
    for state in rows.all():
        counts[str(state)] = counts.get(str(state), 0) + 1
    return counts
