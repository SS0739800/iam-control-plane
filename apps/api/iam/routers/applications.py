"""Listing applications, looking at one, and registering one.

Registering happens by pasting the application's own metadata rather than by
filling in a form of addresses. That is the same decision as registering an
identity provider and it matters more here, not less: the ACS URL is where we post
a signed assertion for a real person, so a mistyped one is a login delivered
somewhere it should not go.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.sql.elements import Label

from iam.api.pagination import MAX_LIMIT, Page, clamp_limit
from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep
from iam.models.application import AppAssignment, Application
from iam.models.enums import ActorType, AppProtocol, AppStatus, AuditOutcome
from iam.models.group import Group
from iam.models.user import User
from iam.saml.metadata import UnreadableMetadata, read_sp_metadata
from iam.schemas.common import GroupRef, UserRef
from iam.schemas.directory import (
    ApplicationDetail,
    ApplicationRegistration,
    ApplicationSummary,
)
from iam.security import Actor, Permission, require

logger = logging.getLogger(__name__)

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


@router.post(
    "",
    response_model=ApplicationDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Register an application from its metadata, or update one",
)
async def register_application(
    payload: ApplicationRegistration,
    request: Request,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
) -> ApplicationDetail:
    """Read an application's metadata and store what it says.

    ``apps:write``, reused rather than given a permission of its own. Registering an
    application is managing an application, and the audience is already the narrowest
    one — admin. Inventing a separate permission would suggest it was a different
    kind of power and then let the two drift apart. The opposite call was made for
    role grants, where ``users:write`` was genuinely *not* an equivalent power.

    The document is pasted in, never fetched from a URL. Same reasoning as
    registering an identity provider, and it applies here for the same reason: our
    server can reach things the person pasting cannot. See
    docs/adr/0006-paste-metadata-do-not-fetch-it.md.

    Registering the same slug again replaces the details, which is how a certificate
    or an address change is handled — paste the new metadata and the row updates.

    Raises:
        HTTPException: 400 if the metadata can't be read or is missing something.
            409 if another slug has already claimed the same entity id.
    """
    try:
        metadata = read_sp_metadata(payload.metadata_xml)
    except UnreadableMetadata as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"That metadata could not be used: {exc}",
        ) from exc

    existing = await session.scalar(select(Application).where(Application.slug == payload.slug))

    # Two slugs pointing at one application would make a login ambiguous: an
    # AuthnRequest names the entity that sent it, not which of our rows to answer
    # against.
    clash = await session.scalar(
        select(Application).where(
            Application.entity_id == metadata.entity_id,
            Application.slug != payload.slug,
        )
    )
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"{metadata.entity_id} is already registered as {clash.slug!r}. "
                "Update that one instead of adding a second name for it."
            ),
        )

    previous_acs = existing.acs_url if existing else None

    application = existing or Application(slug=payload.slug)
    application.name = payload.name
    application.description = payload.description
    application.protocol = AppProtocol.SAML2
    application.status = AppStatus.ACTIVE if payload.enabled else AppStatus.INACTIVE
    application.entity_id = metadata.entity_id
    application.acs_url = metadata.acs_url
    application.slo_url = metadata.slo_url
    application.signing_cert = metadata.signing_cert

    if existing is None:
        session.add(application)
    await session.flush()

    # Where assertions go is the security-relevant fact about an application, so a
    # change to it is called out rather than buried in a list of edited fields. An
    # address moving when nobody moved it is exactly the event worth finding.
    acs_moved = previous_acs is not None and previous_acs != metadata.acs_url

    await append_event(
        session,
        AuditDraft(
            action="application.updated" if existing else "application.registered",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="application",
            target_id=str(application.id),
            target_label=application.slug,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "entity_id": application.entity_id,
                "acs_url": application.acs_url,
                "slo_url": application.slo_url,
                "enabled": payload.enabled,
                "signs_its_requests": metadata.signing_cert is not None,
                "assertion_address_changed": acs_moved,
                "previous_acs_url": previous_acs if acs_moved else None,
            },
        ),
    )
    await session.commit()
    await session.refresh(application)

    logger.info(
        "application.registered",
        extra={
            "slug": application.slug,
            "by": actor.user_name,
            "acs_moved": acs_moved,
        },
    )

    return await get_application(session, application.id)
