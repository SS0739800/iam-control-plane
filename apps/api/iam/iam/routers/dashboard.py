"""The numbers on the front page of the console."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from iam.deps import SessionDep
from iam.models.application import Application
from iam.models.audit import AuditEvent
from iam.models.enums import AppProtocol
from iam.models.group import Group
from iam.models.user import User
from iam.schemas.common import DashboardCounts
from iam.security import Permission, require

router = APIRouter(tags=["dashboard"])


@router.get(
    "/dashboard",
    response_model=DashboardCounts,
    summary="Headline counts",
    dependencies=[Depends(require(Permission.USERS_READ))],
)
async def dashboard(session: SessionDep) -> DashboardCounts:
    """All six counts in one trip to the database.

    Six little subqueries inside one SELECT, instead of six separate queries. This
    is the first thing that loads on every visit, and six round trips to Supabase
    over the internet is a delay you can see. One isn't.
    """
    stmt = select(
        select(func.count()).select_from(User).scalar_subquery().label("users"),
        select(func.count())
        .select_from(User)
        .where(User.active)
        .scalar_subquery()
        .label("active_users"),
        select(func.count()).select_from(Group).scalar_subquery().label("groups"),
        select(func.count()).select_from(Application).scalar_subquery().label("applications"),
        select(func.count())
        .select_from(Application)
        .where(Application.protocol == AppProtocol.SAML2)
        .scalar_subquery()
        .label("sso_applications"),
        select(func.count()).select_from(AuditEvent).scalar_subquery().label("audit_events"),
    )

    row = (await session.execute(stmt)).one()
    return DashboardCounts.model_validate(row._mapping)
