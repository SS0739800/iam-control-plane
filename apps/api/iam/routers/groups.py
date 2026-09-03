"""Listing groups and looking at one."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.sql.elements import Label

from iam.api.pagination import MAX_LIMIT, Page, clamp_limit
from iam.deps import SessionDep
from iam.models.application import AppAssignment, Application
from iam.models.group import Group, GroupMember
from iam.models.user import User
from iam.schemas.common import AppRef, UserRef
from iam.schemas.directory import GroupDetail, GroupSummary
from iam.security import Permission, require

router = APIRouter(prefix="/groups", tags=["groups"])

MEMBER_PREVIEW_LIMIT = 25
"""How many members come back with the group itself. Engineering has 148 in the
demo data and sending all of them every time is wasteful, so the console asks
/members for the rest."""


def _member_count_subquery() -> Label[int]:
    """Count the members of each group.

    A subquery per row rather than a join with GROUP BY, so adding other filters
    to the query later can't make the grouping and filtering interfere and
    quietly produce wrong counts.
    """
    return (
        select(func.count())
        .select_from(GroupMember)
        .where(GroupMember.group_id == Group.id)
        .scalar_subquery()
        .label("member_count")
    )


def _summary(group: Group, member_count: int) -> GroupSummary:
    return GroupSummary(
        id=group.id,
        name=group.name,
        description=group.description,
        hrms_role=group.hrms_role,
        source=group.source,
        member_count=member_count,
    )


@router.get(
    "",
    response_model=Page[GroupSummary],
    summary="List groups",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def list_groups(
    session: SessionDep,
    q: Annotated[str | None, Query(description="Match group name")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[GroupSummary]:
    limit = clamp_limit(limit)
    filters = [Group.name.ilike(f"%{q}%")] if q else []

    total = await session.scalar(select(func.count()).select_from(Group).where(*filters)) or 0

    rows = (
        await session.execute(
            select(Group, _member_count_subquery())
            .where(*filters)
            .order_by(Group.name)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return Page[GroupSummary](
        items=[_summary(group, count) for group, count in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{group_id}",
    response_model=GroupDetail,
    summary="One group",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def get_group(session: SessionDep, group_id: uuid.UUID) -> GroupDetail:
    group = await session.get(Group, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such group")

    member_count = (
        await session.scalar(
            select(func.count()).select_from(GroupMember).where(GroupMember.group_id == group_id)
        )
        or 0
    )

    members = (
        await session.scalars(
            select(User)
            .join(GroupMember, GroupMember.user_id == User.id)
            .where(GroupMember.group_id == group_id)
            .order_by(User.display_name)
            .limit(MEMBER_PREVIEW_LIMIT)
        )
    ).all()

    app_rows = (
        await session.execute(
            select(Application, AppAssignment.role)
            .join(AppAssignment, AppAssignment.application_id == Application.id)
            .where(AppAssignment.group_id == group_id)
            .order_by(Application.name)
        )
    ).all()

    return GroupDetail(
        **_summary(group, member_count).model_dump(),
        external_id=group.external_id,
        created_at=group.created_at,
        updated_at=group.updated_at,
        applications=[
            AppRef(id=app.id, name=app.name, slug=app.slug, protocol=app.protocol, role=role)
            for app, role in app_rows
        ],
        members=[UserRef.model_validate(member) for member in members],
    )


@router.get(
    "/{group_id}/members",
    response_model=Page[UserRef],
    summary="Page through a group's members",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def list_members(
    session: SessionDep,
    group_id: uuid.UUID,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserRef]:
    limit = clamp_limit(limit)

    total = (
        await session.scalar(
            select(func.count()).select_from(GroupMember).where(GroupMember.group_id == group_id)
        )
        or 0
    )

    rows = (
        await session.scalars(
            select(User)
            .join(GroupMember, GroupMember.user_id == User.id)
            .where(GroupMember.group_id == group_id)
            .order_by(User.display_name, User.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return Page[UserRef](
        items=[UserRef.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
