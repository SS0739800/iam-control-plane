"""The user list, one user's details, editing them, and group membership."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select

from iam.api.pagination import MAX_LIMIT, Page, clamp_limit
from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep
from iam.models.application import AppAssignment, Application
from iam.models.enums import ActorType, IdentitySource, MembershipSource, PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.user import User
from iam.schemas.common import AppRef, GroupRef, UserRef
from iam.schemas.directory import UserDetail, UserSummary, UserUpdate
from iam.security import Actor, Permission, require

router = APIRouter(prefix="/users", tags=["users"])

# Fields the identity provider owns once it's created a user. Letting someone edit
# these here is worse than refusing: the next sync puts the old value back, and
# they walk away thinking they fixed it.
IDP_OWNED_FIELDS = frozenset({"department", "job_title"})


def _client_context(request: Request) -> tuple[str | None, str | None]:
    """Where the request came from, for the audit entry."""
    ip = request.client.host if request.client else None
    return ip, request.headers.get("user-agent")


async def _effective_applications(session: SessionDep, user_id: uuid.UUID) -> list[AppRef]:
    """Everything a person can get into, and how they got it.

    Access comes from two places: given to them directly, or given to a group
    they're in. We keep the group name rather than throwing it away, because the
    question helpdesk actually gets asked is "why does this person have
    Salesforce?"
    """
    direct_rows = (
        await session.execute(
            select(Application, AppAssignment.role)
            .join(AppAssignment, AppAssignment.application_id == Application.id)
            .where(AppAssignment.user_id == user_id)
        )
    ).all()

    inherited_rows = (
        await session.execute(
            select(Application, AppAssignment.role, Group.name)
            .join(AppAssignment, AppAssignment.application_id == Application.id)
            .join(Group, Group.id == AppAssignment.group_id)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user_id)
        )
    ).all()

    effective: dict[uuid.UUID, AppRef] = {}

    # Group access goes in first so a direct grant below can overwrite it. If
    # someone has both, "given directly" is the more useful thing to show.
    for app, role, group_name in inherited_rows:
        effective[app.id] = AppRef(
            id=app.id,
            name=app.name,
            slug=app.slug,
            protocol=app.protocol,
            role=role,
            via_group=group_name,
        )

    for app, role in direct_rows:
        effective[app.id] = AppRef(
            id=app.id,
            name=app.name,
            slug=app.slug,
            protocol=app.protocol,
            role=role,
            via_group=None,
        )

    return sorted(effective.values(), key=lambda ref: ref.name)


async def _load_user(session: SessionDep, user_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such user")
    return user


@router.get(
    "",
    response_model=Page[UserSummary],
    summary="List users",
    dependencies=[Depends(require(Permission.USERS_READ))],
)
async def list_users(
    session: SessionDep,
    q: Annotated[str | None, Query(description="Match name, userName or email")] = None,
    active: Annotated[bool | None, Query()] = None,
    department: Annotated[str | None, Query()] = None,
    platform_role: Annotated[PlatformRole | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserSummary]:
    """The user list, filtered and split into pages.

    The filtering and paging happen in Postgres, not the browser. There are 1,284
    users in the demo data; sending all of them so the frontend can filter would
    be slow, and it would also hand out every record to anyone who can load one
    page.
    """
    limit = clamp_limit(limit)
    filters = []

    if q:
        pattern = f"%{q}%"
        filters.append(
            or_(
                User.display_name.ilike(pattern),
                User.user_name.ilike(pattern),
                User.email.ilike(pattern),
            )
        )
    if active is not None:
        filters.append(User.active.is_(active))
    if department:
        filters.append(User.department == department)
    if platform_role is not None:
        filters.append(User.platform_role == platform_role)

    total = await session.scalar(select(func.count()).select_from(User).where(*filters)) or 0

    rows = (
        await session.scalars(
            select(User)
            .where(*filters)
            .order_by(User.display_name, User.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return Page[UserSummary](
        items=[UserSummary.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{user_id}",
    response_model=UserDetail,
    summary="One user, with effective access",
    dependencies=[Depends(require(Permission.USERS_READ))],
)
async def get_user(session: SessionDep, user_id: uuid.UUID) -> UserDetail:
    user = await _load_user(session, user_id)

    groups = (
        await session.scalars(
            select(Group)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user_id)
            .order_by(Group.name)
        )
    ).all()

    manager = await session.get(User, user.manager_id) if user.manager_id else None

    return UserDetail(
        **UserSummary.model_validate(user).model_dump(),
        given_name=user.given_name,
        family_name=user.family_name,
        employee_number=user.employee_number,
        external_id=user.external_id,
        manager=UserRef.model_validate(manager) if manager else None,
        created_at=user.created_at,
        updated_at=user.updated_at,
        groups=[GroupRef.model_validate(group) for group in groups],
        applications=await _effective_applications(session, user_id),
    )


@router.patch(
    "/{user_id}",
    response_model=UserDetail,
    summary="Update a user",
)
async def update_user(
    request: Request,
    session: SessionDep,
    user_id: uuid.UUID,
    payload: UserUpdate,
    actor: Annotated[Actor, Depends(require(Permission.USERS_WRITE))],
) -> UserDetail:
    """Change some fields on a user and write down what changed.

    Raises:
        HTTPException: 409 if the field belongs to the identity provider and this
            user came from SCIM.
    """
    user = await _load_user(session, user_id)
    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    if user.source is IdentitySource.SCIM:
        conflicting = IDP_OWNED_FIELDS & changes.keys()
        if conflicting:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=(
                    f"{', '.join(sorted(conflicting))} is managed by the identity "
                    "provider for this user. Change it there instead — an edit "
                    "here gets overwritten on the next sync."
                ),
            )

    before = {field: getattr(user, field) for field in changes}
    for field, value in changes.items():
        setattr(user, field, value)

    ip, user_agent = _client_context(request)
    await append_event(
        session,
        AuditDraft(
            action="user.updated",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            target_type="user",
            target_id=str(user.id),
            target_label=user.user_name,
            ip_address=ip,
            user_agent=user_agent,
            detail={
                "changed": {
                    field: {"from": str(before[field]), "to": str(value)}
                    for field, value in changes.items()
                }
            },
        ),
    )
    await session.commit()

    # Refreshed before reading anything off this row again. updated_at has a
    # server-side onupdate, so the UPDATE leaves that one column expired, and
    # touching it outside an await is a MissingGreenlet under async — which is
    # exactly what this endpoint did for every edit until there was a test for it.
    await session.refresh(user)

    return await get_user(session, user_id)


@router.put(
    "/{user_id}/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    # Has to be spelled out. Otherwise FastAPI sees `-> None` and treats None as a
    # response body type, then complains that a 204 isn't allowed to have a body.
    response_model=None,
    summary="Add a user to a group",
)
async def add_to_group(
    request: Request,
    session: SessionDep,
    user_id: uuid.UUID,
    group_id: uuid.UUID,
    actor: Annotated[Actor, Depends(require(Permission.USERS_WRITE, Permission.GROUPS_WRITE))],
) -> None:
    """Safe to call twice. Adding someone already in the group just does nothing."""
    user = await _load_user(session, user_id)

    group = await session.get(Group, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such group")

    existing = await session.get(GroupMember, {"group_id": group_id, "user_id": user_id})
    if existing is not None:
        return

    session.add(
        GroupMember(
            group_id=group_id,
            user_id=user_id,
            # Somebody chose this in the console, so the rule engine leaves it alone.
            source=MembershipSource.MANUAL,
        )
    )

    ip, user_agent = _client_context(request)
    await append_event(
        session,
        AuditDraft(
            action="group.member_added",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            target_type="group",
            target_id=str(group.id),
            target_label=group.name,
            ip_address=ip,
            user_agent=user_agent,
            detail={"user_id": str(user.id), "user_name": user.user_name},
        ),
    )
    await session.commit()


@router.delete(
    "/{user_id}/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Remove a user from a group",
)
async def remove_from_group(
    request: Request,
    session: SessionDep,
    user_id: uuid.UUID,
    group_id: uuid.UUID,
    actor: Annotated[Actor, Depends(require(Permission.USERS_WRITE, Permission.GROUPS_WRITE))],
) -> None:
    membership = await session.get(GroupMember, {"group_id": group_id, "user_id": user_id})
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not a member of that group")

    user = await _load_user(session, user_id)
    group = await session.get(Group, group_id)
    group_name = group.name if group else str(group_id)

    await session.delete(membership)

    ip, user_agent = _client_context(request)
    await append_event(
        session,
        AuditDraft(
            action="group.member_removed",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            target_type="group",
            target_id=str(group_id),
            target_label=group_name,
            ip_address=ip,
            user_agent=user_agent,
            detail={"user_id": str(user.id), "user_name": user.user_name},
        ),
    )
    await session.commit()
