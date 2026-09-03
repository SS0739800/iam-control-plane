"""Managing the systems that provision into us, from the console.

This is the screen that makes a SCIM token a thing with a lifecycle: issued
by somebody, visible in a list, revocable, and with a record of when it was
last used.

Guarded by the same permission as registering an identity provider, since
both answer "which outside system do we believe about who people are" - one
at login, the other continuously.

Revoking marks the row rather than deleting it, so "that sync stopped on the
3rd because we revoked it" is still answerable later.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload

from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.deps import SessionDep, SettingsDep
from iam.models.application import Application
from iam.models.audit import AuditEvent
from iam.models.enums import ActorType, AuditOutcome, IdentitySource, LinkState
from iam.models.group import Group
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.provisioning import (
    AlreadyRunning,
    OutboundScim,
    PushFailed,
    UnusableTarget,
    check,
    count_waiting,
    reconcile,
)
from iam.schemas.provisioning import (
    ProvisioningActivity,
    ProvisioningOverview,
    ScimClientCreate,
    ScimClientIssued,
    ScimClientRevoke,
    ScimClientSummary,
)
from iam.schemas.targets import (
    ProbeResult,
    ProvisioningLinkOut,
    ProvisioningTargetCreate,
    ProvisioningTargetSummary,
    ProvisioningTargetUpdate,
    SyncResult,
)
from iam.secrets import CannotDecrypt, decrypt, encrypt
from iam.security import Actor, Permission, require
from iam.tokens import hash_token, new_token

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

    `users_from_login` is worth watching: someone arriving by login means
    SCIM hadn't told us about them yet. Fine occasionally, a sign of a
    broken or narrow sync if it keeps happening.
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

    Not filtered to usable ones - a revoked token is exactly what someone
    is looking for when working out why a sync stopped.
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

    The token is in this response and nowhere else. We keep only its hash,
    so there's nothing to show later even if the screen offered to.

    The audit entry records that a token was issued and by whom, not the
    token itself.
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

    Marked rather than deleted, so the audit log's references to it still
    resolve - useful since revoking usually means you think it leaked.

    Revoking an already-revoked client leaves the original reason and
    timestamp alone; when it was cut off is the fact that matters.
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

    A view over the audit log, filtered to entries a provisioning system
    made, so someone doesn't have to scroll the whole log to see what's
    actually arriving.
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

    # "SCIM client <authentik>" -> "authentik". Prefer the detail field when
    # present, since that survives any change to how the label is formatted.
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


# ==================================================== the systems we push into
#
# Guarded by apps:write, same as registering an application's SAML wiring - a
# provisioning target is config that belongs to one application (unique per
# application, cascade-deleted with it). Contrast with idp:write, which is
# about outside systems we *believe* about identity; this is about outside
# systems that *receive* our identity data.
#
# Nothing here returns the token. It's stored encrypted, not hashed, so we
# could return it - that's exactly why there's no field for it.
#
# There's no hook on granting access. Someone clicking "give this person
# access" shouldn't wait on a downstream or have their grant fail because
# another server is down. So access changes are recorded and the accounts
# follow on the next sync (the button below, or a scheduled call) - this
# system has no background worker, so it doesn't pretend a request can push
# instantly.


async def _target_or_404(session: SessionDep, target_id: uuid.UUID) -> ProvisioningTarget:
    """One target, with its application already loaded.

    Eager-loaded because the summary reads `target.application.name`, and a
    lazy load there raises MissingGreenlet under async - a confusing error
    that names greenlets, not the relationship, so it's slow to place.
    """
    target = await session.scalar(
        select(ProvisioningTarget)
        .where(ProvisioningTarget.id == target_id)
        .options(selectinload(ProvisioningTarget.application))
    )
    if target is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"No provisioning target with id {target_id}."
        )
    return target


async def _counts(session: SessionDep, target_id: uuid.UUID) -> dict[str, int]:
    """How many links are in each state, for the summary."""
    rows = await session.execute(
        select(ProvisioningLink.state, func.count())
        .where(ProvisioningLink.target_id == target_id)
        .group_by(ProvisioningLink.state)
    )
    by_state = dict(rows.tuples().all())
    return {
        "accounts_active": by_state.get(LinkState.ACTIVE, 0),
        "accounts_pending": by_state.get(LinkState.PENDING, 0),
        "accounts_failed": by_state.get(LinkState.FAILED, 0),
        "accounts_orphaned": by_state.get(LinkState.ORPHANED, 0),
        "accounts_deprovisioned": by_state.get(LinkState.DEPROVISIONED, 0),
    }


async def _target_summary(
    session: SessionDep, target: ProvisioningTarget
) -> ProvisioningTargetSummary:
    return ProvisioningTargetSummary(
        id=target.id,
        application_id=target.application_id,
        application_name=target.application.name,
        application_slug=target.application.slug,
        base_url=target.base_url,
        enabled=target.enabled,
        address_concession=target.address_concession,
        last_sync_at=target.last_sync_at,
        last_sync_ok=target.last_sync_ok,
        last_error=target.last_error,
        created_at=target.created_at,
        updated_at=target.updated_at,
        **await _counts(session, target.id),
        # Separate from the state counts - those describe what the links
        # are, this describes what a sync would do.
        accounts_waiting_to_push=await count_waiting(session, target),
    )


def _check_address(url: str, settings: Settings) -> str | None:
    """Apply ADR 0007, and return whatever rule had to be relaxed.

    Raises:
        HTTPException: 400 if the address is one we refuse.
    """
    try:
        decision = check(
            url,
            is_production=settings.is_production,
            allow_private=settings.allow_private_provisioning_targets,
        )
    except UnusableTarget as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return decision.concession


@router.get(
    "/targets",
    response_model=list[ProvisioningTargetSummary],
    summary="The systems we push accounts into",
    dependencies=[Depends(require(Permission.APPS_READ))],
)
async def list_targets(session: SessionDep) -> list[ProvisioningTargetSummary]:
    """Every target, switched off ones included.

    A disabled target is exactly what someone is looking for when working
    out why a downstream stopped receiving people.
    """
    rows = await session.scalars(
        select(ProvisioningTarget)
        .options(selectinload(ProvisioningTarget.application))
        .order_by(ProvisioningTarget.base_url)
    )
    return [await _target_summary(session, target) for target in rows.all()]


@router.post(
    "/targets",
    response_model=ProvisioningTargetSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Register a system to push accounts into",
)
async def create_target(
    payload: ProvisioningTargetCreate,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
) -> ProvisioningTargetSummary:
    """Register a downstream, after checking we are willing to talk to it.

    The address is checked here, not on every push - see ADR 0007. A
    hostname that later resolves somewhere private isn't caught by this, but
    the row being reviewable is the actual control, not the resolve check.

    Raises:
        HTTPException: 400 for an address we refuse, 404 for a missing application,
            409 if that application already has a target.
    """
    application = await session.get(Application, payload.application_id)
    if application is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"No application with id {payload.application_id}.",
        )

    existing = await session.scalar(
        select(ProvisioningTarget).where(
            ProvisioningTarget.application_id == payload.application_id
        )
    )
    if existing is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"{application.name} already has a provisioning target. Two would race "
                "each other writing the same accounts - update that one instead."
            ),
        )

    concession = _check_address(payload.base_url, settings)

    target = ProvisioningTarget(
        application_id=payload.application_id,
        base_url=payload.base_url.strip(),
        token_encrypted=encrypt(payload.token, settings),
        enabled=payload.enabled,
        address_concession=concession,
    )
    session.add(target)
    await session.flush()

    await append_event(
        session,
        AuditDraft(
            action="provisioning_target.registered",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="provisioning_target",
            target_id=str(target.id),
            target_label=target.base_url,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "application": application.slug,
                "base_url": target.base_url,
                "enabled": target.enabled,
                # Recorded so a relaxed rule is findable later, not just
                # visible on a page someone may never open.
                "address_concession": concession,
            },
        ),
    )
    await session.commit()

    logger.info(
        "provisioning_target.registered",
        extra={"base_url": target.base_url, "by": actor.user_name},
    )

    return await _target_summary(session, target)


@router.patch(
    "/targets/{target_id}",
    response_model=ProvisioningTargetSummary,
    summary="Change a target, or rotate its token",
)
async def update_target(
    target_id: uuid.UUID,
    payload: ProvisioningTargetUpdate,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
) -> ProvisioningTargetSummary:
    """Edit a target. Sending a token replaces it; there is no way to read the old one."""
    target = await _target_or_404(session, target_id)
    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No fields to update.")

    if payload.base_url is not None:
        target.address_concession = _check_address(payload.base_url, settings)
        target.base_url = payload.base_url.strip()

    if payload.token is not None:
        target.token_encrypted = encrypt(payload.token, settings)
        # A new token means the old failure is probably stale - stop showing it.
        target.last_error = None

    if payload.enabled is not None:
        target.enabled = payload.enabled

    await append_event(
        session,
        AuditDraft(
            action="provisioning_target.updated",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="provisioning_target",
            target_id=str(target.id),
            target_label=target.base_url,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                # The token itself is never recorded, only that it changed.
                "token_rotated": payload.token is not None,
                "changed": sorted(key for key in changes if key != "token"),
                "base_url": target.base_url,
                "enabled": target.enabled,
            },
        ),
    )
    await session.commit()

    # Re-fetched rather than reused: updated_at has a server-side onupdate,
    # so the UPDATE leaves that column expired, and reading it would lazy
    # load - MissingGreenlet under async. Same bug hit iam/routers/users.py,
    # so after an UPDATE, always re-read through a query that eager loads
    # what the response needs.
    return await _target_summary(session, await _target_or_404(session, target_id))


@router.delete(
    "/targets/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Stop provisioning into a system",
)
async def delete_target(
    target_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
) -> None:
    """Remove a target and forget which account belonged to whom.

    Does not deactivate anybody downstream. Silently switching off a few
    hundred accounts on the way out would be a much bigger action than the
    button suggests - disable the target and run one more sync to
    deprovision people first, then delete it.

    The audit entry records how many links were forgotten, since that's the
    number someone will want afterwards.
    """
    target = await _target_or_404(session, target_id)

    counts = await _counts(session, target_id)
    still_live = counts["accounts_active"]

    await append_event(
        session,
        AuditDraft(
            action="provisioning_target.deleted",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="provisioning_target",
            target_id=str(target.id),
            target_label=target.base_url,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "application": target.application.slug,
                "links_forgotten": sum(counts.values()),
                "accounts_left_active_downstream": still_live,
                "note": (
                    "Deleting a target does not deactivate anybody. Accounts left "
                    "active downstream stay active."
                ),
            },
        ),
    )

    await session.delete(target)
    await session.commit()

    logger.warning(
        "provisioning_target.deleted",
        extra={
            "base_url": target.base_url,
            "by": actor.user_name,
            "accounts_left_active_downstream": still_live,
        },
    )


@router.post(
    "/targets/{target_id}/probe",
    response_model=ProbeResult,
    summary="Check a target answers and accepts our token",
)
async def probe_target(
    target_id: uuid.UUID,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
) -> ProbeResult:
    """Read the target's ServiceProviderConfig, which describes nobody.

    Good to call right after registering a target - it proves the address
    and token work before anyone depends on them, and changes nothing.
    """
    target = await _target_or_404(session, target_id)

    try:
        client = OutboundScim(
            base_url=target.scim_root, token=decrypt(target.token_encrypted, settings)
        )
        detail = await client.probe()
    except (PushFailed, CannotDecrypt) as exc:
        return ProbeResult(reachable=False, detail=str(exc))

    return ProbeResult(reachable=True, detail=detail)


@router.post(
    "/targets/{target_id}/sync",
    response_model=SyncResult,
    summary="Push accounts to a target now",
)
async def sync_target(
    target_id: uuid.UUID,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.APPS_WRITE))],
    force: Annotated[
        bool,
        Query(
            description=(
                "Push everybody regardless of whether they look unchanged, and retry "
                "links that have run out of attempts."
            )
        ),
    ] = False,
) -> SyncResult:
    """Reconcile the target's accounts with who is entitled to them.

    Runs in the request rather than a background job, so a large first sync
    takes a while. There's no worker to drain a queue, so a job id nobody
    could poll would be worse.
    """
    target = await _target_or_404(session, target_id)

    try:
        outcome = await reconcile(
            session, target, settings, now=dt.datetime.now(dt.UTC), force=force
        )
    except AlreadyRunning as busy:
        # The background sweep has it, or another admin just pressed this.
        # 409, not 500: the request is fine, it just needs to wait.
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(busy)) from busy

    logger.info(
        "provisioning.sync_requested",
        extra={
            "base_url": target.base_url,
            "by": actor.user_name,
            "correlation_id": str(outcome.correlation_id),
        },
    )

    return SyncResult(
        correlation_id=outcome.correlation_id,
        created=outcome.created,
        adopted=outcome.adopted,
        updated=outcome.updated,
        deactivated=outcome.deactivated,
        reactivated=outcome.reactivated,
        unchanged=outcome.unchanged,
        failed=outcome.failed,
        skipped_exhausted=outcome.skipped_exhausted,
        stopped_early=outcome.stopped_early,
        ok=outcome.ok,
    )


@router.get(
    "/targets/{target_id}/accounts",
    response_model=list[ProvisioningLinkOut],
    summary="Who has an account in this system, and who does not",
    dependencies=[Depends(require(Permission.APPS_READ))],
)
async def target_accounts(
    target_id: uuid.UUID,
    session: SessionDep,
    state: Annotated[
        LinkState | None,
        Query(description="Only this state. 'orphaned' is the one worth looking at."),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[ProvisioningLinkOut]:
    """The links, newest problems first.

    Ordered so failures and orphans come before working accounts - a list of
    two hundred working accounts isn't what anyone opens this for.
    """
    await _target_or_404(session, target_id)

    conditions = [ProvisioningLink.target_id == target_id]
    if state is not None:
        conditions.append(ProvisioningLink.state == state)

    rows = await session.execute(
        select(ProvisioningLink, User)
        .join(User, User.id == ProvisioningLink.user_id)
        .where(*conditions)
        .order_by(
            # Orphaned first: someone still has access we meant to remove.
            case(
                (ProvisioningLink.state == LinkState.ORPHANED, 0),
                (ProvisioningLink.state == LinkState.FAILED, 1),
                (ProvisioningLink.state == LinkState.PENDING, 2),
                else_=3,
            ),
            User.user_name,
        )
        .limit(limit)
    )

    return [
        ProvisioningLinkOut(
            user_id=person.id,
            user_name=person.user_name,
            display_name=person.display_name,
            active=person.active,
            remote_id=link.remote_id,
            state=link.state,
            last_pushed_at=link.last_pushed_at,
            last_error=link.last_error,
            attempts=link.attempts,
        )
        for link, person in rows.tuples().all()
    ]
