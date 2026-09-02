"""The numbers on the front page of the console."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select

from iam.deps import SessionDep
from iam.models.access import RoleGrant
from iam.models.application import Application
from iam.models.audit import AuditEvent
from iam.models.enums import AppProtocol, PlatformRole
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
    """Every count in one trip to the database.

    Little subqueries inside one SELECT, instead of one query each. This is the first
    thing that loads on every visit, and that many round trips to a hosted database
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
        # Counted here rather than read from users.platform_role, which is a cache.
        # This number is the difference between "somebody can fix this" and "somebody
        # needs a shell", so it should not depend on a cache being right.
        select(func.count())
        .select_from(RoleGrant)
        .join(User, User.id == RoleGrant.user_id)
        .where(
            RoleGrant.role == PlatformRole.ADMIN,
            RoleGrant.revoked_at.is_(None),
            or_(RoleGrant.expires_at.is_(None), RoleGrant.expires_at > func.now()),
            User.active.is_(True),
        )
        .scalar_subquery()
        .label("live_admins"),
    )

    row = (await session.execute(stmt)).one()
    return DashboardCounts.model_validate(row._mapping)
