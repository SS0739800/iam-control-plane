"""Granting and revoking console roles.

Before this, the only way to make somebody an admin was the dev stand-in or
a hand-written UPDATE.

Two things worth knowing:

This requires roles:write, not users:write. Helpdesk holds users:write, and
if granting a role were an ordinary user edit, anyone who can fix a
misspelled name could make themselves admin.

The last admin can't be removed. There's no root account or back door, so
if the last admin goes, nobody can grant anything again except by a
hand-written UPDATE — the thing this module exists to replace.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from iam.access import (
    Granter,
    RoleGrantRefused,
    count_live_admins,
    grant_role,
    history,
    live_grant,
    revoke_role,
)
from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep
from iam.models.access import RoleGrant
from iam.models.enums import ActorType, AuditOutcome, PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.user import User
from iam.schemas.access import AccessSummary, RoleGrantCreate, RoleGrantOut, RoleGrantRevoke
from iam.security import Actor, Permission, require

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users/{user_id}", tags=["access"])


def _out(grant: RoleGrant, *, now: dt.datetime) -> RoleGrantOut:
    return RoleGrantOut(
        id=grant.id,
        role=grant.role,
        source=grant.source,
        reason=grant.reason,
        granted_by_label=grant.granted_by_label,
        created_at=grant.created_at,
        expires_at=grant.expires_at,
        revoked_at=grant.revoked_at,
        revoked_by_label=grant.revoked_by_label,
        revoked_reason=grant.revoked_reason,
        live=grant.is_live(now=now),
    )


async def _load_user(session: SessionDep, user_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No user with id {user_id}.")
    return user


async def _refuse_if_last_admin(
    session: SessionDep, user: User, *, now: dt.datetime, doing: str
) -> None:
    """Stop the change if it would leave nobody able to grant anything.

    Raises:
        HTTPException: 409, because the request is fine but the state of the world
            makes it unacceptable.
    """
    current = await live_grant(session, user.id, now=now)
    if current is None or current.role != PlatformRole.ADMIN:
        return

    if await count_live_admins(session, now=now) > 1:
        return

    raise HTTPException(
        status.HTTP_409_CONFLICT,
        detail=(
            f"{user.display_name} is the only admin left, so {doing} would leave "
            "nobody able to grant anything — including the ability to undo it. "
            "Make somebody else an admin first."
        ),
    )


@router.get(
    "/role-grants",
    response_model=list[RoleGrantOut],
    summary="Every role this person has ever had",
    dependencies=[Depends(require(Permission.ROLES_READ))],
)
async def list_role_grants(user_id: uuid.UUID, session: SessionDep) -> list[RoleGrantOut]:
    """The full history, newest first.

    Revoked and expired grants included, because "what could they do last month"
    is most of what an access review is asking.
    """
    await _load_user(session, user_id)
    now = dt.datetime.now(dt.UTC)
    return [_out(grant, now=now) for grant in await history(session, user_id)]


@router.get(
    "/access",
    response_model=AccessSummary,
    summary="Everything this person has, and why",
    dependencies=[Depends(require(Permission.ROLES_READ))],
)
async def access_summary(user_id: uuid.UUID, session: SessionDep) -> AccessSummary:
    """One person's access, gathered in one place."""
    user = await _load_user(session, user_id)
    now = dt.datetime.now(dt.UTC)

    current = await live_grant(session, user.id, now=now)
    groups = (
        await session.scalars(
            select(Group.name)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user.id)
            .order_by(Group.name)
        )
    ).all()

    return AccessSummary(
        user_id=user.id,
        user_name=user.user_name,
        display_name=user.display_name,
        active=user.active,
        role=user.platform_role,
        role_granted_by=current.granted_by_label if current else None,
        role_granted_at=current.created_at if current else None,
        role_expires_at=current.expires_at if current else None,
        groups=list(groups),
        grant_history=[_out(grant, now=now) for grant in await history(session, user.id)],
    )


@router.post(
    "/role-grants",
    response_model=RoleGrantOut,
    status_code=status.HTTP_201_CREATED,
    summary="Give this person a console role",
)
async def create_role_grant(
    user_id: uuid.UUID,
    payload: RoleGrantCreate,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.ROLES_WRITE))],
) -> RoleGrantOut:
    """Grant a role, replacing whatever they had.

    Raises:
        HTTPException: 400 if the grant doesn't make sense — 'employee', an expiry
            already in the past, or a deactivated person. 409 if it would demote
            the last admin.
    """
    user = await _load_user(session, user_id)
    now = dt.datetime.now(dt.UTC)

    # Granting somebody a lesser role replaces their admin grant, so this is a
    # demotion in disguise and gets the same guard as revoking.
    if payload.role != PlatformRole.ADMIN:
        await _refuse_if_last_admin(session, user, now=now, doing="changing their role")

    try:
        grant = await grant_role(
            session,
            user,
            role=payload.role,
            granter=Granter(user_id=actor.user_id, label=actor.audit_label),
            now=now,
            reason=payload.reason,
            expires_at=payload.expires_at,
        )
    except RoleGrantRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await append_event(
        session,
        AuditDraft(
            action="role.granted",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="user",
            target_id=str(user.id),
            target_label=user.user_name,
            detail={
                "role": str(payload.role),
                "reason": payload.reason,
                "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
                # Recorded since "who made whom an admin" is usually the
                # first question after something goes wrong.
                "granted_by": actor.user_name,
                "self_grant": actor.user_id == user.id,
            },
        ),
    )
    await session.commit()
    await session.refresh(grant)

    logger.info(
        "access.role_granted_via_api",
        extra={"user": user.user_name, "role": str(payload.role), "by": actor.user_name},
    )

    return _out(grant, now=now)


@router.delete(
    "/role-grants",
    response_model=AccessSummary,
    summary="Take this person's console role away",
)
async def delete_role_grant(
    user_id: uuid.UUID,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.ROLES_WRITE))],
    payload: RoleGrantRevoke | None = None,
) -> AccessSummary:
    """Revoke their role, putting them back to employee.

    Revoking when there is nothing to revoke is not an error — the end state is
    what was asked for.

    Raises:
        HTTPException: 409 if they are the last admin.
    """
    user = await _load_user(session, user_id)
    now = dt.datetime.now(dt.UTC)
    reason = (payload or RoleGrantRevoke()).reason

    await _refuse_if_last_admin(session, user, now=now, doing="revoking it")

    revoked = await revoke_role(
        session,
        user,
        granter=Granter(user_id=actor.user_id, label=actor.audit_label),
        now=now,
        reason=reason,
    )

    if revoked is not None:
        await append_event(
            session,
            AuditDraft(
                action="role.revoked",
                actor_type=ActorType.USER,
                actor_id=actor.user_id,
                actor_label=actor.audit_label,
                outcome=AuditOutcome.SUCCESS,
                target_type="user",
                target_id=str(user.id),
                target_label=user.user_name,
                detail={
                    "role": str(revoked.role),
                    "reason": reason,
                    "revoked_by": actor.user_name,
                    "self_revoke": actor.user_id == user.id,
                },
            ),
        )

    await session.commit()

    logger.info(
        "access.role_revoked_via_api",
        extra={"user": user.user_name, "by": actor.user_name, "reason": reason},
    )

    return await access_summary(user_id, session)
