"""/scim/v2/Groups — the provider telling us who is in what.

Membership is the whole point of this endpoint. Creating a group is nearly
trivial; keeping its members in step is where the work and the mistakes are.

Two things shape everything below.

**Membership is written here, not on the person.** A provider adds somebody by
PATCHing the group, and `User.groups` in the SCIM output is the read-only
reflection of that. Allowing both directions would mean two ways to write the
same rows and a race between them.

**PATCH add is not PUT.** ``add`` puts somebody in without disturbing anyone
else; ``replace`` on ``members`` sets the list to exactly what arrived, which
means removing everybody not in it. Confusing the two empties groups, and it
empties them quietly — the request succeeds and the members are simply gone.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response, status
from sqlalchemy import delete, func, select

from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep, SettingsDep
from iam.models.enums import ActorType, AuditOutcome, IdentitySource
from iam.models.group import Group, GroupMember
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.schemas.scim import PatchRequest, ScimGroup
from iam.scim.auth import ScimClientDep
from iam.scim.constants import GROUP_RESOURCE, SCIM_PREFIX
from iam.scim.errors import already_exists, bad_path, bad_value, not_found
from iam.scim.filters import parse_group_filter
from iam.scim.mapping import group_to_scim
from iam.scim.responses import list_json, paging, resource_json

logger = logging.getLogger(__name__)

router = APIRouter(prefix=f"{SCIM_PREFIX}/Groups", tags=["scim"])


async def _load(session: SessionDep, group_id: str) -> Group:
    """One group by id, or a SCIM 404."""
    try:
        parsed = uuid.UUID(group_id)
    except ValueError as exc:
        raise not_found(GROUP_RESOURCE, group_id) from exc

    group = await session.scalar(select(Group).where(Group.id == parsed))
    if group is None:
        raise not_found(GROUP_RESOURCE, group_id)
    return group


async def _members(session: SessionDep, group: Group) -> list[User]:
    return list(
        (
            await session.scalars(
                select(User)
                .join(GroupMember)
                .where(GroupMember.group_id == group.id)
                .order_by(User.display_name)
            )
        ).all()
    )


async def _record(
    session: SessionDep,
    request: Request,
    client: ScimClient,
    *,
    action: str,
    group: Group,
    detail: dict[str, Any],
) -> None:
    await append_event(
        session,
        AuditDraft(
            action=action,
            actor_type=ActorType.IDP,
            actor_label=f"SCIM client <{client.name}>",
            outcome=AuditOutcome.SUCCESS,
            target_type="group",
            target_id=str(group.id),
            target_label=group.name,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"scim_client": client.name, **detail},
        ),
    )


def _member_ids(value: Any) -> list[uuid.UUID]:
    """Read the user ids out of a members value.

    SCIM sends members as a list of objects with a ``value`` holding the id, and
    providers also send a bare list of ids or a single object. All three are
    accepted because the alternative is refusing a sync over punctuation.

    Ids that aren't ids are skipped rather than failing the request. A provider
    referring to somebody who was deleted upstream should not be able to wedge
    the whole group sync.
    """
    if value is None:
        return []

    entries = value if isinstance(value, list) else [value]

    ids: list[uuid.UUID] = []
    for entry in entries:
        raw = entry.get("value") if isinstance(entry, dict) else entry
        if not raw:
            continue
        try:
            ids.append(uuid.UUID(str(raw)))
        except ValueError:
            logger.warning("scim.group_member_not_an_id", extra={"value": str(raw)[:80]})
    return ids


async def _existing_members(session: SessionDep, group: Group) -> set[uuid.UUID]:
    rows = await session.scalars(
        select(GroupMember.user_id).where(GroupMember.group_id == group.id)
    )
    return set(rows.all())


async def _real_users(session: SessionDep, ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """Which of these ids are people we actually have.

    Checked before inserting, because a membership row pointing at nobody is a
    foreign key error that fails the whole request — and one stale id in a list
    of two hundred should not lose the other hundred and ninety-nine.
    """
    if not ids:
        return set()
    rows = await session.scalars(select(User.id).where(User.id.in_(ids)))
    return set(rows.all())


async def _add_members(session: SessionDep, group: Group, ids: list[uuid.UUID]) -> int:
    already = await _existing_members(session, group)
    real = await _real_users(session, ids)

    added = 0
    for user_id in ids:
        if user_id in already or user_id not in real:
            continue
        session.add(GroupMember(group_id=group.id, user_id=user_id))
        already.add(user_id)
        added += 1
    return added


async def _remove_members(session: SessionDep, group: Group, ids: list[uuid.UUID]) -> int:
    if not ids:
        return 0
    result = await session.execute(
        delete(GroupMember).where(GroupMember.group_id == group.id, GroupMember.user_id.in_(ids))
    )
    return int(result.rowcount or 0)


async def _replace_members(
    session: SessionDep, group: Group, ids: list[uuid.UUID]
) -> tuple[int, int]:
    """Make the membership exactly this list.

    The destructive one. Anybody not in the list is removed, which is what
    ``replace`` means and why it must never be reached by a request that said
    ``add``.
    """
    wanted = set(await _real_users(session, ids))
    current = await _existing_members(session, group)

    removed = await _remove_members(session, group, sorted(current - wanted))
    added = await _add_members(session, group, sorted(wanted - current))
    return added, removed


@router.get("", summary="List or search groups")
async def list_groups(
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
    filter_: Annotated[
        str | None,
        Query(alias="filter", description='A single comparison, e.g. displayName eq "Engineering"'),
    ] = None,
    start_index: Annotated[int | None, Query(alias="startIndex", ge=1)] = None,
    count: Annotated[int | None, Query(ge=0)] = None,
) -> Response:
    conditions = []
    if filter_:
        comparison = parse_group_filter(filter_)
        column = getattr(Group, comparison.column)
        conditions.append(func.lower(column) == str(comparison.value).lower())

    offset, limit = paging(start_index, count)

    total = await session.scalar(select(func.count()).select_from(Group).where(*conditions)) or 0

    rows = (
        await session.scalars(
            select(Group)
            .where(*conditions)
            .order_by(Group.created_at, Group.id)
            .offset(offset)
            .limit(limit)
        )
    ).all()

    resources = [
        group_to_scim(group, base_url=settings.base_url, members=await _members(session, group))
        for group in rows
    ]

    return list_json(resources, total=total, start_index=offset + 1)


@router.get("/{group_id}", summary="One group")
async def get_group(
    group_id: str, session: SessionDep, settings: SettingsDep, client: ScimClientDep
) -> Response:
    group = await _load(session, group_id)
    return resource_json(
        group_to_scim(group, base_url=settings.base_url, members=await _members(session, group))
    )


@router.post("", summary="Create a group", status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: ScimGroup,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Create a group, with whoever it says is in it."""
    name = payload.display_name.strip()
    if not name:
        raise bad_value("displayName cannot be empty.")

    existing = await session.scalar(select(Group).where(func.lower(Group.name) == name.lower()))
    if existing is not None:
        raise already_exists("displayName", name)

    group = Group(name=name, external_id=payload.external_id, source=IdentitySource.SCIM)
    session.add(group)
    await session.flush()

    added = await _add_members(
        session, group, _member_ids([m.model_dump() for m in payload.members])
    )

    await _record(
        session,
        request,
        client,
        action="group.created",
        group=group,
        detail={"source": "scim", "members_added": added},
    )
    await session.commit()
    await session.refresh(group)

    logger.info("scim.group_created", extra={"group_id": str(group.id), "members": added})

    return resource_json(
        group_to_scim(group, base_url=settings.base_url, members=await _members(session, group)),
        status_code=status.HTTP_201_CREATED,
    )


@router.put("/{group_id}", summary="Replace a group")
async def replace_group(
    group_id: str,
    payload: ScimGroup,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Set the group to exactly what arrived, members included.

    PUT means replace, so the membership becomes the list in the document and
    anybody missing from it is removed. That is the destructive reading and it is
    the correct one here — unlike PATCH add, which only ever puts people in.
    """
    group = await _load(session, group_id)

    name = payload.display_name.strip()
    if not name:
        raise bad_value("displayName cannot be empty.")

    if name.lower() != group.name.lower():
        clash = await session.scalar(
            select(Group).where(func.lower(Group.name) == name.lower(), Group.id != group.id)
        )
        if clash is not None:
            raise already_exists("displayName", name)

    renamed = group.name != name
    group.name = name
    if payload.external_id is not None:
        group.external_id = payload.external_id

    added, removed = await _replace_members(
        session, group, _member_ids([m.model_dump() for m in payload.members])
    )

    if renamed or added or removed:
        await _record(
            session,
            request,
            client,
            action="group.updated",
            group=group,
            detail={
                "via": "scim.put",
                "renamed": renamed,
                "members_added": added,
                "members_removed": removed,
            },
        )

    await session.commit()
    await session.refresh(group)

    return resource_json(
        group_to_scim(group, base_url=settings.base_url, members=await _members(session, group))
    )


@router.patch("/{group_id}", summary="Change part of a group")
async def patch_group(
    group_id: str,
    patch: PatchRequest,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    client: ScimClientDep,
) -> Response:
    """Add or remove members, or rename the group.

    This is how membership actually changes in practice: somebody joins a team
    upstream and the provider sends one ``add`` with one member in it.

    The distinction that matters is between ``add`` and ``replace`` on
    ``members``. Add puts people in and leaves everyone else alone. Replace sets
    the list to exactly what arrived, removing anybody absent from it. Treating
    an add as a replace empties groups, and does it quietly.
    """
    group = await _load(session, group_id)

    added = removed = 0
    renamed = False

    for operation in patch.operations:
        path = (operation.path or "").strip().lower()

        # A pathless operation carries a partial resource, the way Entra sends
        # them: {"op": "replace", "value": {"displayName": "..."}}.
        if not path and isinstance(operation.value, dict):
            new_name = operation.value.get("displayName") or operation.value.get("displayname")
            members = operation.value.get("members")
            if new_name:
                renamed = renamed or await _rename(session, group, str(new_name))
            if members is not None:
                more, fewer = await _replace_members(session, group, _member_ids(members))
                added += more
                removed += fewer
            continue

        if path in ("displayname", "name"):
            renamed = renamed or await _rename(session, group, str(operation.value))
            continue

        # members, or members[value eq "..."] which is how a provider names one
        # person to remove.
        if not path.startswith("members"):
            raise bad_path(
                f"Cannot patch {operation.path!r} on a Group. Supported: displayName, members."
            )

        ids = _member_ids(operation.value)

        # members[value eq "<id>"] with no value: the id is in the path itself.
        if not ids and "eq" in path:
            quoted = path.split("eq", 1)[1].strip().strip('"]').strip('"')
            ids = _member_ids(quoted)

        if operation.operation == "add":
            added += await _add_members(session, group, ids)
        elif operation.operation == "remove":
            # No ids at all means "remove every member", which the spec allows
            # and which a provider means when it clears a group.
            removed += await (
                _remove_members(session, group, ids)
                if ids
                else _remove_members(
                    session, group, sorted(await _existing_members(session, group))
                )
            )
        else:
            more, fewer = await _replace_members(session, group, ids)
            added += more
            removed += fewer

    if renamed or added or removed:
        await _record(
            session,
            request,
            client,
            action="group.updated",
            group=group,
            detail={
                "via": "scim.patch",
                "renamed": renamed,
                "members_added": added,
                "members_removed": removed,
            },
        )

    await session.commit()
    await session.refresh(group)

    return resource_json(
        group_to_scim(group, base_url=settings.base_url, members=await _members(session, group))
    )


async def _rename(session: SessionDep, group: Group, name: str) -> bool:
    cleaned = name.strip()
    if not cleaned:
        raise bad_value("displayName cannot be empty.")
    if cleaned.lower() == group.name.lower():
        group.name = cleaned
        return False

    clash = await session.scalar(
        select(Group).where(func.lower(Group.name) == cleaned.lower(), Group.id != group.id)
    )
    if clash is not None:
        raise already_exists("displayName", cleaned)

    group.name = cleaned
    return True


@router.delete("/{group_id}", summary="Delete a group", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    request: Request,
    session: SessionDep,
    client: ScimClientDep,
) -> Response:
    """Remove a group. Unlike a person, this really does delete.

    A group is a container, not somebody's record. Keeping an emptied group
    around forever would clutter the directory without answering any question the
    audit log doesn't already answer — the entries saying who was in it and when
    they were removed survive this, because the audit log is append-only.

    The membership rows go with it through the cascade; the people do not.
    """
    group = await _load(session, group_id)
    member_count = len(await _members(session, group))

    await _record(
        session,
        request,
        client,
        action="group.deleted",
        group=group,
        detail={"via": "scim.delete", "members_at_deletion": member_count},
    )

    await session.delete(group)
    await session.commit()

    logger.info("scim.group_deleted", extra={"group_id": group_id, "members": member_count})

    return Response(status_code=status.HTTP_204_NO_CONTENT)
