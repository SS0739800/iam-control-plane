"""/scim/v2/Users — the provider writing people into our directory.

This is the endpoint that makes P2's just-in-time creation a fallback rather than
the plan. Somebody created here exists from the moment HR added them upstream,
with their department and their manager, instead of appearing as a bare username
the first time they happen to log in.

Two behaviours are worth reading before changing anything.

**DELETE deactivates.** It does not delete. The row stays, `active` goes false,
and every session they have is cut. That is what a provider means by DELETE —
"this person has left" — and it is the only reading compatible with an audit log
that still has to answer what they had access to. See the handler.

**Everything is idempotent.** Providers re-send during a full sync, retry on
timeouts, and generally assume that doing the same thing twice is safe. Creating
somebody who exists answers 409 with the id, deactivating somebody already
inactive answers 200, and neither writes an audit entry saying nothing changed.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep, SettingsDep
from iam.models.enums import ActorType, AuditOutcome, IdentitySource
from iam.models.group import Group, GroupMember
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.saml.sessions import RevokedReason, revoke_all_for_user
from iam.schemas.scim import PatchRequest, ScimUser
from iam.scim.auth import ScimClientDep
from iam.scim.constants import SCIM_PREFIX, USER_RESOURCE
from iam.scim.errors import already_exists, bad_path, bad_value, not_found
from iam.scim.filters import parse_user_filter
from iam.scim.mapping import apply_user, user_fields_from_scim, user_to_scim
from iam.scim.responses import list_json, paging, resource_json

logger = logging.getLogger(__name__)

router = APIRouter(prefix=f"{SCIM_PREFIX}/Users", tags=["scim"])


async def _load(session: SessionDep, user_id: str) -> User:
    """One person by id, or a SCIM 404.

    The id comes off the URL as whatever the provider put there, so a malformed
    one has to answer 404 rather than raising on the UUID parse. A provider
    asking about a resource that cannot exist is asking about one that doesn't.
    """
    try:
        parsed = uuid.UUID(user_id)
    except ValueError as exc:
        raise not_found(USER_RESOURCE, user_id) from exc

    user = await session.scalar(
        select(User).where(User.id == parsed).options(selectinload(User.groups))
    )
    if user is None:
        raise not_found(USER_RESOURCE, user_id)
    return user


async def _groups_of(session: SessionDep, user: User) -> list[Group]:
    return list(
        (
            await session.scalars(
                select(Group).join(GroupMember).where(GroupMember.user_id == user.id)
            )
        ).all()
    )


async def _record(
    session: SessionDep,
    request: Request,
    client: ScimClient,
    *,
    action: str,
    user: User,
    detail: dict[str, Any],
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
) -> None:
    """Write down what the provider did.

    Attributed to the SCIM client rather than to a person, because no person was
    involved. "authentik deactivated this account at 02:14" is the sentence
    somebody needs six months later, and it is not available if this is logged as
    though the user did it to themselves.
    """
    await append_event(
        session,
        AuditDraft(
            action=action,
            actor_type=ActorType.IDP,
            actor_label=f"SCIM client <{client.name}>",
            outcome=outcome,
            target_type="user",
            target_id=str(user.id),
            target_label=user.user_name,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"scim_client": client.name, **detail},
        ),
    )


@router.get("", summary="List or search people")
async def list_users(
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
    filter_: Annotated[
        str | None,
        Query(alias="filter", description='A single comparison, e.g. userName eq "ada@demo.local"'),
    ] = None,
    start_index: Annotated[int | None, Query(alias="startIndex", ge=1)] = None,
    count: Annotated[int | None, Query(ge=0)] = None,
) -> Response:
    """People, filtered and paged the way SCIM asks for.

    Almost every call here is a provider asking "do you already have this one?"
    before deciding whether to create or update. That is why an unreadable filter
    is an error rather than being ignored — see iam/scim/filters.py.
    """
    conditions = []
    if filter_:
        comparison = parse_user_filter(filter_)
        column = getattr(User, comparison.column)
        # Case-insensitive on the text columns, because providers are not
        # consistent about the case of an email address and matching exactly
        # would create a second account for the same person.
        conditions.append(
            column.is_(comparison.value)
            if comparison.is_boolean
            else func.lower(column) == str(comparison.value).lower()
        )

    offset, limit = paging(start_index, count)

    total = await session.scalar(select(func.count()).select_from(User).where(*conditions)) or 0

    rows = (
        await session.scalars(
            select(User)
            .where(*conditions)
            .order_by(User.created_at, User.id)
            .offset(offset)
            .limit(limit)
        )
    ).all()

    resources = []
    for user in rows:
        resources.append(
            user_to_scim(user, base_url=settings.base_url, groups=await _groups_of(session, user))
        )

    return list_json(resources, total=total, start_index=offset + 1)


@router.get("/{user_id}", summary="One person")
async def get_user(
    user_id: str, session: SessionDep, settings: SettingsDep, client: ScimClientDep
) -> Response:
    user = await _load(session, user_id)
    return resource_json(
        user_to_scim(user, base_url=settings.base_url, groups=await _groups_of(session, user))
    )


@router.post("", summary="Create a person", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: ScimUser,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Add somebody the provider has told us about.

    A userName that already exists answers 409 with scimType uniqueness rather
    than creating a duplicate. That is not just correctness about the spec: it is
    what lets a provider recover, because it reads that code and switches to
    updating the person instead of reporting a failed sync forever.

    Somebody who already exists gets a 409 whatever created them, including
    somebody P2 created just-in-time at their first login. That is not a dead end:
    a provider searches by userName before creating, finds them, and updates them
    instead — and that update is what promotes a just-in-time record to a
    SCIM-managed one. See _adopt.
    """
    values = user_fields_from_scim(payload)
    user_name = str(values["user_name"])

    existing = await session.scalar(
        select(User).where(func.lower(User.user_name) == user_name.lower())
    )
    if existing is not None:
        raise already_exists("userName", user_name)

    if payload.external_id:
        clash = await session.scalar(select(User).where(User.external_id == payload.external_id))
        if clash is not None:
            raise already_exists("externalId", payload.external_id)

    user = User(source=IdentitySource.SCIM)
    apply_user(user, values)
    session.add(user)
    await session.flush()

    await _record(
        session,
        request,
        client,
        action="user.created",
        user=user,
        detail={"source": "scim", "external_id": user.external_id},
    )
    await session.commit()
    await session.refresh(user)

    logger.info("scim.user_created", extra={"user_id": str(user.id), "client": client.name})

    return resource_json(
        user_to_scim(user, base_url=settings.base_url), status_code=status.HTTP_201_CREATED
    )


@router.put("/{user_id}", summary="Replace a person")
async def replace_user(
    user_id: str,
    payload: ScimUser,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Overwrite what the provider owns, leave the rest alone.

    "Replace" in SCIM means the resource, not the row. Fields the document does
    not carry keep their values rather than being blanked, and fields SCIM is not
    allowed to write — what somebody may do in this console, most of all — are
    untouched whatever the document says. See WRITABLE_USER_FIELDS.
    """
    user = await _load(session, user_id)
    values = user_fields_from_scim(payload)

    new_name = str(values["user_name"])
    if new_name.lower() != user.user_name.lower():
        clash = await session.scalar(
            select(User).where(func.lower(User.user_name) == new_name.lower(), User.id != user.id)
        )
        if clash is not None:
            raise already_exists("userName", new_name)

    was_active = user.active
    changed = apply_user(user, values)
    adopted = _adopt(user)

    if changed or adopted:
        await _record(
            session,
            request,
            client,
            action="user.updated",
            user=user,
            detail={"changed": list(changed), "via": "scim.put", "adopted": adopted},
        )
    if was_active and not user.active:
        await _deactivate_sessions(session, request, client, user)

    await session.commit()
    await session.refresh(user)

    return resource_json(
        user_to_scim(user, base_url=settings.base_url, groups=await _groups_of(session, user))
    )


def _adopt(user: User) -> bool:
    """Promote a just-in-time record to a SCIM-managed one, if that's what happened.

    Somebody created by logging in exists as a bare username. The first time the
    provider writes to them, they stop being that: the directory upstream now owns
    the record, and the console should stop offering to hand-edit fields the next
    sync would overwrite anyway.

    Deliberately decided here rather than read off the document. `source` is not
    in WRITABLE_USER_FIELDS, so a provider cannot set it to anything it likes —
    this is us drawing a conclusion from the fact that SCIM wrote at all.
    """
    if user.source is IdentitySource.JIT:
        user.source = IdentitySource.SCIM
        return True
    return False


async def _deactivate_sessions(
    session: SessionDep, request: Request, client: ScimClient, user: User
) -> None:
    """Cut every session somebody has, because they were just switched off.

    The part that makes deprovisioning mean something. Setting a flag while
    leaving them signed in for the next eight hours is the failure mode this
    whole design exists to avoid — see the note on SamlSession about why sessions
    are rows.
    """
    ended = await revoke_all_for_user(
        session,
        user.id,
        reason=RevokedReason.USER_DEACTIVATED,
        now=dt.datetime.now(dt.UTC),
    )
    if ended:
        await _record(
            session,
            request,
            client,
            action="user.sessions_revoked",
            user=user,
            detail={"sessions_ended": ended, "reason": RevokedReason.USER_DEACTIVATED},
        )
    logger.info(
        "scim.user_deactivated",
        extra={"user_id": str(user.id), "sessions_ended": ended, "client": client.name},
    )


def _patch_values(patch: PatchRequest) -> dict[str, object]:
    """Work out what a PATCH is asking to change.

    Supports the two shapes providers send:

        {"op": "replace", "path": "active", "value": false}
        {"op": "replace", "value": {"active": false}}

    The second is Entra's habit — no path, and the value is a partial resource.
    Handling only the first works in testing against authentik and then quietly
    ignores every deactivation Entra sends, which is the worst possible failure
    for this endpoint.

    Raises:
        ScimError: The operation is one we don't support, or names a path we
            can't act on. Refused rather than ignored: a PATCH that answers 200
            and changes nothing tells the provider the person was deactivated
            when they were not.
    """
    values: dict[str, object] = {}

    for operation in patch.operations:
        if operation.operation == "remove":
            # Removing an attribute from a person is not something a provider
            # does for the fields we hold; removing group membership is a PATCH
            # on the group, not on the person.
            raise bad_path(
                "remove is not supported on a User. Group membership is changed by "
                "PATCHing the Group."
            )

        if operation.path:
            attribute = operation.path.strip().lower()
            mapped = _PATCHABLE.get(attribute)
            if mapped is None:
                raise bad_path(
                    f"Cannot patch {operation.path!r}. Supported: "
                    f"{', '.join(sorted(_PATCHABLE))}."
                )
            values[mapped] = operation.value
            continue

        if isinstance(operation.value, dict):
            for key, value in operation.value.items():
                mapped = _PATCHABLE.get(str(key).lower())
                if mapped is not None:
                    values[mapped] = value
            continue

        raise bad_value("A patch operation needs either a path or an object value.")

    return values


# What a PATCH may touch, by the SCIM attribute name the provider uses.
# `active` is the one that matters; the rest are here because providers correct
# a name or an email through PATCH rather than PUT.
_PATCHABLE = {
    "active": "active",
    "username": "user_name",
    "displayname": "display_name",
    "externalid": "external_id",
    "name.givenname": "given_name",
    "name.familyname": "family_name",
    'emails[type eq "work"].value': "email",
    "emails.value": "email",
}


@router.patch("/{user_id}", summary="Change part of a person")
async def patch_user(
    user_id: str,
    patch: PatchRequest,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Apply a partial change. This is how deprovisioning arrives.

    When somebody leaves, a provider does not delete them — it sends
    ``replace active false``. That single operation is the most important thing
    this endpoint handles, and it has to end their sessions as well as set the
    flag.
    """
    user = await _load(session, user_id)
    values = _patch_values(patch)

    if "active" in values and not isinstance(values["active"], bool):
        raise bad_value("active has to be true or false.")

    was_active = user.active
    changed = apply_user(user, values)
    adopted = _adopt(user)

    if changed or adopted:
        await _record(
            session,
            request,
            client,
            action="user.updated",
            user=user,
            detail={"changed": list(changed), "via": "scim.patch", "adopted": adopted},
        )

    if was_active and not user.active:
        await _deactivate_sessions(session, request, client, user)

    await session.commit()
    await session.refresh(user)

    return resource_json(
        user_to_scim(user, base_url=settings.base_url, groups=await _groups_of(session, user))
    )


@router.delete("/{user_id}", summary="Deactivate a person", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    request: Request,
    session: SessionDep,
    client: ScimClientDep,
) -> Response:
    """Switch somebody off. Deliberately not a delete.

    A provider sending DELETE means "this person has left", and the useful
    response to that is to end their access, not to erase the evidence of what
    they had. The row stays, active goes false, and their sessions are cut — the
    same thing PATCH active false does, because they mean the same thing.

    Answers 204 either way. A provider retrying a delete it already sent should
    not get an error for being thorough.
    """
    user = await _load(session, user_id)

    if user.active:
        user.active = False
        await _record(
            session,
            request,
            client,
            action="user.deactivated",
            user=user,
            detail={"via": "scim.delete", "note": "row kept; SCIM delete means deprovision"},
        )
        await _deactivate_sessions(session, request, client, user)

    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
