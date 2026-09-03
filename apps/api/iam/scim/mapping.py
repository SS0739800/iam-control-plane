"""Turning our rows into SCIM resources, and SCIM documents back into rows.

Kept apart from the endpoints so the shape of what we send lives in one
readable function instead of being assembled inline in a handler. This is
also the only place that decides what SCIM is allowed to overwrite - a
security question, not just formatting. See apply_user.

No database access here. Everything takes objects already loaded and returns
plain data, so all of it is tested without Postgres.
"""

from __future__ import annotations

import datetime as dt
import hashlib

from iam.models.group import Group
from iam.models.user import User
from iam.schemas.scim import (
    Email,
    EnterpriseUser,
    MemberRef,
    Meta,
    Name,
    ScimGroup,
    ScimUser,
)
from iam.scim.constants import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_RESOURCE,
    GROUP_SCHEMA,
    SCIM_PREFIX,
    USER_RESOURCE,
    USER_SCHEMA,
)


def _version(updated_at: dt.datetime | None) -> str:
    """An ETag for a resource.

    Derived from the last-modified time instead of stored, since there's no
    other use for it. Stable, cheap, and changes exactly when the row does.
    """
    stamp = (updated_at or dt.datetime.now(dt.UTC)).isoformat()
    return f'W/"{hashlib.sha256(stamp.encode()).hexdigest()[:16]}"'


def _meta(
    resource_type: str, resource_id: str, created: dt.datetime, updated: dt.datetime, base_url: str
) -> Meta:
    root = base_url.rstrip("/")
    plural = f"{resource_type}s"
    return Meta(
        resource_type=resource_type,
        created=created,
        last_modified=updated,
        location=f"{root}{SCIM_PREFIX}/{plural}/{resource_id}",
        version=_version(updated),
    )


def user_to_scim(user: User, *, base_url: str, groups: list[Group] | None = None) -> ScimUser:
    """Our person, as SCIM sees them.

    The name is sent both split and formatted, since providers read whichever
    one they were built around - leaving one out is a common cause of a
    display name that never updates.
    """
    root = base_url.rstrip("/")

    formatted = " ".join(part for part in (user.given_name, user.family_name) if part)

    enterprise = None
    if user.employee_number or user.department or user.manager_id:
        enterprise = EnterpriseUser(
            employee_number=user.employee_number,
            department=user.department,
            manager=(
                MemberRef(
                    value=str(user.manager_id),
                    ref=f"{root}{SCIM_PREFIX}/Users/{user.manager_id}",
                )
                if user.manager_id
                else None
            ),
        )

    return ScimUser(
        schemas=[USER_SCHEMA] + ([ENTERPRISE_USER_SCHEMA] if enterprise else []),
        id=str(user.id),
        external_id=user.external_id,
        user_name=user.user_name,
        name=Name(
            given_name=user.given_name,
            family_name=user.family_name,
            formatted=formatted or user.display_name,
        ),
        display_name=user.display_name,
        emails=[Email(value=user.email, type="work", primary=True)] if user.email else [],
        active=user.active,
        groups=[
            MemberRef(
                value=str(group.id),
                display=group.name,
                ref=f"{root}{SCIM_PREFIX}/Groups/{group.id}",
                type="direct",
            )
            for group in (groups or [])
        ],
        enterprise=enterprise,
        meta=_meta(USER_RESOURCE, str(user.id), user.created_at, user.updated_at, base_url),
    )


def group_to_scim(group: Group, *, base_url: str, members: list[User] | None = None) -> ScimGroup:
    root = base_url.rstrip("/")
    return ScimGroup(
        schemas=[GROUP_SCHEMA],
        id=str(group.id),
        external_id=group.external_id,
        display_name=group.name,
        members=[
            MemberRef(
                value=str(member.id),
                display=member.display_name,
                ref=f"{root}{SCIM_PREFIX}/Users/{member.id}",
                type=USER_RESOURCE,
            )
            for member in (members or [])
        ],
        meta=_meta(GROUP_RESOURCE, str(group.id), group.created_at, group.updated_at, base_url),
    )


# What SCIM is allowed to write. Everything else on the row is ours.
#
# platform_role is not in here: a provider can create, name, or deactivate
# someone, but it must never be able to grant console admin by editing a
# directory record.
WRITABLE_USER_FIELDS = (
    "user_name",
    "email",
    "given_name",
    "family_name",
    "display_name",
    "active",
    "external_id",
    "employee_number",
    "department",
)


def user_fields_from_scim(scim: ScimUser) -> dict[str, object]:
    """The columns a SCIM document is asking us to set.

    Only includes fields the document actually carries. A provider sending a
    partial resource on PUT shouldn't have the omitted fields read as "set
    these to null" - otherwise a sync would blank everybody's department
    instead of just tidying a record.
    """
    values: dict[str, object] = {
        "user_name": scim.user_name,
        "active": scim.active,
    }

    email = scim.primary_email
    if email:
        values["email"] = email

    if scim.external_id is not None:
        values["external_id"] = scim.external_id

    if scim.name is not None:
        if scim.name.given_name is not None:
            values["given_name"] = scim.name.given_name
        if scim.name.family_name is not None:
            values["family_name"] = scim.name.family_name

    display = scim.display_name or (
        " ".join(
            part
            for part in (
                scim.name.given_name if scim.name else None,
                scim.name.family_name if scim.name else None,
            )
            if part
        )
        or scim.user_name
    )
    values["display_name"] = display

    if scim.enterprise is not None:
        if scim.enterprise.employee_number is not None:
            values["employee_number"] = scim.enterprise.employee_number
        if scim.enterprise.department is not None:
            values["department"] = scim.enterprise.department

    return values


def apply_user(user: User, values: dict[str, object]) -> tuple[str, ...]:
    """Write the allowed fields onto a person, and say what changed.

    Anything outside WRITABLE_USER_FIELDS is dropped, not raised. A provider
    sending a field it shouldn't isn't reason to fail the whole sync - just
    ignore that field, which matches how the spec treats read-only attributes.
    """
    changed: list[str] = []

    for field, value in values.items():
        if field not in WRITABLE_USER_FIELDS:
            continue
        if getattr(user, field) != value:
            setattr(user, field, value)
            changed.append(field)

    return tuple(changed)
