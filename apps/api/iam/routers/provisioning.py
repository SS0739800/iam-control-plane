"""Managing the systems that provision into us, from the console.

A credential nobody can see or revoke without opening a database client is not
really being managed. This is the screen that makes a SCIM token a thing with a
lifecycle: issued by somebody, visible in a list, revocable, and with a record of
when it was last used.

Guarded by the same permission as registering an identity provider, and for the
same reason. Both answer "which outside system do we believe about who people
are" — one at the moment somebody logs in, the other continuously. Whoever can
decide that can decide who exists here.

Revoking marks the row rather than deleting it. "That sync stopped on the 3rd
because we revoked it" is a question somebody asks later, and it is unanswerable
if the row is gone.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep
from iam.models.audit import AuditEvent
from iam.models.enums import ActorType, AuditOutcome, IdentitySource
from iam.models.group import Group
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.schemas.provisioning import (
    ProvisioningActivity,
    ProvisioningOverview,
    ScimClientCreate,
    ScimClientIssued,
    ScimClientRevoke,
    ScimClientSummary,
)
from iam.security import Actor, Permission, require
from iam.security.tokens import hash_token, new_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/provisioning", tags=["provisioning"])

SCIM_ACTOR_PREFIX = "SCIM client <"


def _summary(client: ScimClient) -> ScimClientSummary:
    return ScimClientSummary(
        id=client.id,
        name=client.name,
        description=client.description,
        enabled=client.enabled,
        created_at=client.created_at,
        last_used_at=client.last_used_at,
        revoked_at=client.revoked_at,
        revoked_reason=client.revoked_reason,
        usable=client.is_usable,
    )


@router.get(
    "/overview",
    response_model=ProvisioningOverview,
    summary="What provisioning has done to this directory",
    dependencies=[Depends(require(Permission.IDP_READ))],
)
async def overview(session: SessionDep) -> ProvisioningOverview:
    """The numbers that say whether the sync is doing its job.

    ``users_from_login`` is the one worth watching. Somebody arriving by logging
    in means SCIM had not told us about them yet, which is fine occasionally and a
    sign of a broken or narrow sync if it keeps happening.
    """
    users_from_scim = (
        await session.scalar(
            select(func.count()).select_from(User).where(User.source == IdentitySource.SCIM)
        )
        or 0
    )
    users_from_login = (
        await session.scalar(
            select(func.count()).select_from(User).where(User.source == IdentitySource.JIT)
        )
        or 0
    )
    groups_from_scim = (
        await session.scalar(
            select(func.count()).select_from(Group).where(Group.source == IdentitySource.SCIM)
        )
        or 0
    )
    active_clients = (
        await session.scalar(
            select(func.count())
            .select_from(ScimClient)
            .where(ScimClient.enabled.is_(True), ScimClient.revoked_at.is_(None))
        )
        or 0
    )
    last_sync = await session.scalar(
        select(func.max(AuditEvent.occurred_at)).where(
            AuditEvent.actor_label.startswith(SCIM_ACTOR_PREFIX)
        )
    )

    return ProvisioningOverview(
        users_from_scim=users_from_scim,
        users_from_login=users_from_login,
        groups_from_scim=groups_from_scim,
        active_clients=active_clients,
        last_sync_at=last_sync,
    )


@router.get(
    "/clients",
    response_model=list[ScimClientSummary],
    summary="The systems allowed to write to the directory",
    dependencies=[Depends(require(Permission.IDP_READ))],
)
async def list_clients(session: SessionDep) -> list[ScimClientSummary]:
    """Every client, revoked ones included.

    Not filtered to the usable ones. A revoked token is exactly what somebody is
    looking for when they are working out why a sync stopped.
    """
    rows = (await session.scalars(select(ScimClient).order_by(ScimClient.created_at.desc()))).all()
    return [_summary(client) for client in rows]


@router.post(
    "/clients",
    response_model=ScimClientIssued,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a token for a provisioning system",
)
async def issue_client(
    payload: ScimClientCreate,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.IDP_WRITE))],
) -> ScimClientIssued:
    """Create a client and hand back its token, once.

    The token is in this response and nowhere else, ever. We keep only its hash,
    so there is nothing to show later even if the screen offered to.

    The audit entry records that a token was issued and by whom. It does not
    record the token, which would rather defeat the point of not storing it.
    """
    name = payload.name.strip()

    existing = await session.scalar(select(ScimClient).where(ScimClient.name == name))
    if existing is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"A provisioning client called {name!r} already exists. Names have to "
                "be unique, or the audit log can't say which one acted."
            ),
        )

    token = new_token()
    client = ScimClient(
        name=name,
        description=payload.description,
        token_hash=hash_token(token),
        enabled=True,
    )
    session.add(client)
    await session.flush()

    await append_event(
        session,
        AuditDraft(
            action="scim_client.issued",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="scim_client",
            target_id=str(client.id),
            target_label=client.name,
            detail={"description": client.description},
        ),
    )
    await session.commit()
    await session.refresh(client)

    logger.info("scim_client.issued", extra={"client": client.name, "by": actor.user_name})

    return ScimClientIssued(**_summary(client).model_dump(), token=token)


@router.post(
    "/clients/{client_id}/revoke",
    response_model=ScimClientSummary,
    summary="Stop accepting a token",
)
async def revoke_client(
    client_id: uuid.UUID,
    payload: ScimClientRevoke,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.IDP_WRITE))],
) -> ScimClientSummary:
    """Stop a token working, and record why.

    Marked rather than deleted. Revoking one is the thing you do when you think it
    has leaked, and that is precisely when you want the row to survive so the
    audit log's references to it still resolve.

    Revoking an already-revoked client leaves the original reason and timestamp
    alone. When it was cut off is the fact that matters.
    """
    client = await session.scalar(select(ScimClient).where(ScimClient.id == client_id))
    if client is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"No provisioning client with id {client_id}."
        )

    if client.revoked_at is None:
        client.revoked_at = dt.datetime.now(dt.UTC)
        client.revoked_reason = payload.reason
        client.enabled = False

        await append_event(
            session,
            AuditDraft(
                action="scim_client.revoked",
                actor_type=ActorType.USER,
                actor_id=actor.user_id,
                actor_label=actor.audit_label,
                outcome=AuditOutcome.SUCCESS,
                target_type="scim_client",
                target_id=str(client.id),
                target_label=client.name,
                detail={"reason": payload.reason},
            ),
        )
        await session.commit()
        await session.refresh(client)

        logger.warning(
            "scim_client.revoked",
            extra={"client": client.name, "by": actor.user_name, "reason": payload.reason},
        )

    return _summary(client)


@router.get(
    "/activity",
    response_model=list[ProvisioningActivity],
    summary="What the provisioning systems have been doing",
    dependencies=[Depends(require(Permission.IDP_READ))],
)
async def activity(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> list[ProvisioningActivity]:
    """Recent directory writes that came from a SCIM client.

    A view over the audit log, filtered to entries a provisioning system made. It
    answers the question this screen exists for — "is anything actually arriving,
    and what" — without making somebody scroll the whole log looking for it.
    """
    rows = (
        await session.scalars(
            select(AuditEvent)
            .where(AuditEvent.actor_label.startswith(SCIM_ACTOR_PREFIX))
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        )
    ).all()

    return [_activity(event) for event in rows]


def _activity(event: AuditEvent) -> ProvisioningActivity:
    detail: dict[str, Any] = event.detail if isinstance(event.detail, dict) else {}

    # "SCIM client <authentik>" -> "authentik". Read from the detail when it's
    # there, because that survives any change to how the label is formatted.
    client = detail.get("scim_client")
    if not client and event.actor_label.startswith(SCIM_ACTOR_PREFIX):
        client = event.actor_label[len(SCIM_ACTOR_PREFIX) :].rstrip(">")

    return ProvisioningActivity(
        id=event.id,
        occurred_at=event.occurred_at,
        action=event.action,
        client=str(client) if client else None,
        target=event.target_label,
        outcome=str(event.outcome),
        summary=_describe(detail),
    )


def _describe(detail: dict[str, Any]) -> str | None:
    """A short line saying what changed, when the entry carries enough to tell."""
    changed = detail.get("changed")
    if isinstance(changed, list) and changed:
        return f"changed {', '.join(str(field) for field in changed)}"

    added = detail.get("members_added")
    removed = detail.get("members_removed")
    if added or removed:
        parts = []
        if added:
            parts.append(f"{added} added")
        if removed:
            parts.append(f"{removed} removed")
        return ", ".join(parts)

    if ended := detail.get("sessions_ended"):
        return f"{ended} session(s) ended"

    if reason := detail.get("reason"):
        return str(reason)

    return None
