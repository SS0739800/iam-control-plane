"""Listing apps and looking at one.

Read-only for now. Adding a new SAML app means generating keys and swapping
metadata files with it, which belongs with the P5 work rather than being a form
that writes rows.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.sql.elements import Label

from iam.api.pagination import MAX_LIMIT, Page, clamp_limit
from iam.deps import SessionDep
from iam.models.application import AppAssignment, Application
from iam.models.enums import AppProtocol, AppStatus
from iam.models.group import Group
from iam.models.user import User
from iam.schemas.common import GroupRef, UserRef
from iam.schemas.directory import ApplicationDetail, ApplicationSummary
from iam.security import Permission, require

router = APIRouter(prefix="/applications", tags=["applications"])


def _assignment_count_subquery() -> Label[int]:
    return (
        select(func.count())
        .select_from(AppAssignment)
        .where(AppAssignment.application_id == Application.id)
        .scalar_subquery()
        .label("assignment_count")
    )


def _summary(app: Application, assignment_count: int) -> ApplicationSummary:
    return ApplicationSummary(
        id=app.id,
        name=app.name,
        slug=app.slug,
        description=app.description,
        protocol=app.protocol,
        status=app.status,
        assignment_count=assignment_count,
    )


@router.get(
    "",
    response_model=Page[ApplicationSummary],
    summary="List applications",
    dependencies=[Depends(require(Permission.APPS_READ))],
)
async def list_applications(
    session: SessionDep,
    q: Annotated[str | None, Query(description="Match name or slug")] = None,
    protocol: Annotated[AppProtocol | None, Query()] = None,
    app_status: Annotated[AppStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ApplicationSummary]:
    limit = clamp_limit(limit)
    filters = []

    if q:
        pattern = f"%{q}%"
        filters.append(or_(Application.name.ilike(pattern), Application.slug.ilike(pattern)))
    if protocol is not None:
        filters.append(Application.protocol == protocol)
    if app_status is not None:
        filters.append(Application.status == app_status)

    total = await session.scalar(select(func.count()).select_from(Application).where(*filters)) or 0

    rows = (
        await session.execute(
            select(Application, _assignment_count_subquery())
            .where(*filters)
            .order_by(Application.name)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return Page[ApplicationSummary](
        items=[_summary(app, count) for app, count in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{app_id}",
    response_model=ApplicationDetail,
    summary="One application, with its SAML wiring and assignments",
    dependencies=[Depends(require(Permission.APPS_READ))],
)
async def get_application(session: SessionDep, app_id: uuid.UUID) -> ApplicationDetail:
    app = await session.get(Application, app_id)
    if app is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such application")

    assignment_count = (
        await session.scalar(
            select(func.count())
            .select_from(AppAssignment)
            .where(AppAssignment.application_id == app_id)
        )
        or 0
    )

    groups = (
        await session.scalars(
            select(Group)
            .join(AppAssignment, AppAssignment.group_id == Group.id)
            .where(AppAssignment.application_id == app_id)
            .order_by(Group.name)
        )
    ).all()

    users = (
        await session.scalars(
            select(User)
            .join(AppAssignment, AppAssignment.user_id == User.id)
            .where(AppAssignment.application_id == app_id)
            .order_by(User.display_name)
        )
    ).all()

    return ApplicationDetail(
        **_summary(app, assignment_count).model_dump(),
        entity_id=app.entity_id,
        acs_url=app.acs_url,
        slo_url=app.slo_url,
        nameid_format=app.nameid_format,
        signing_cert=app.signing_cert,
        created_at=app.created_at,
        updated_at=app.updated_at,
        assigned_groups=[GroupRef.model_validate(group) for group in groups],
        assigned_users=[UserRef.model_validate(user) for user in users],
    )
