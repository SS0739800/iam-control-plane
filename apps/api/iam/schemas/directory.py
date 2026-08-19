"""Users, groups and apps, as the API sends them.

Two shapes each: a Summary for lists and a Detail for a single record. Keeping
them apart means the list query doesn't have to join membership and access tables
it isn't going to show. With 1,284 users that's the difference between a fast page
and a slow one.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import (
    AppProtocol,
    AppStatus,
    IdentitySource,
    PlatformRole,
)
from iam.schemas.common import AppRef, GroupRef, UserRef

# ---------------------------------------------------------------------- users


class UserSummary(BaseModel):
    """One row in the user list."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_name: str
    display_name: str
    email: str
    active: bool
    department: str | None
    job_title: str | None
    platform_role: PlatformRole
    source: IdentitySource


class UserDetail(UserSummary):
    """Everything about one person, including what they can get into."""

    given_name: str | None
    family_name: str | None
    employee_number: str | None
    external_id: str | None
    manager: UserRef | None
    created_at: dt.datetime
    updated_at: dt.datetime

    groups: list[GroupRef]
    applications: list[AppRef] = Field(
        description=(
            "Everything they can actually get into: given to them directly plus "
            "anything that comes from a group they're in."
        )
    )


class UserUpdate(BaseModel):
    """The fields you're allowed to change. Leave a field out and it stays as is.

    A short list on purpose. Login name, email and external id belong to the
    identity provider for anyone it created, so editing them here would just get
    undone on the next sync.
    """

    model_config = ConfigDict(extra="forbid")

    active: bool | None = None
    department: str | None = None
    job_title: str | None = None

    # platform_role is deliberately absent. It used to be here, and it was a hole:
    # helpdesk holds users:write, so editing a user was a way around roles:write
    # and straight to admin. It would also write the cached role with no grant
    # behind it, which is the drift the grant table exists to prevent. Roles are
    # granted at POST /api/users/{id}/role-grants and nowhere else.


# --------------------------------------------------------------------- groups


class GroupSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    hrms_role: str | None
    source: IdentitySource
    member_count: int


class GroupDetail(GroupSummary):
    external_id: str | None
    created_at: dt.datetime
    updated_at: dt.datetime

    applications: list[AppRef]
    members: list[UserRef] = Field(
        description=(
            "Only the first page of members. Use /api/groups/{id}/members to page "
            "through a big group."
        )
    )


# --------------------------------------------------------------- applications


class ApplicationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    protocol: AppProtocol
    status: AppStatus
    assignment_count: int


class ApplicationDetail(ApplicationSummary):
    """Everything on the app page, including its SAML settings.

    The SAML fields are what iam/routers/idp.py reads to answer a login, so they are
    shown rather than hidden: a mistyped entity id is much easier to spot on a page
    than by reading the database, and it is the difference between an application
    working and every login for it being refused as an unknown issuer.
    """

    entity_id: str | None
    acs_url: str | None
    slo_url: str | None
    nameid_format: str | None
    signing_cert: str | None = Field(
        default=None,
        description="The SP's public certificate. Public by definition — it is "
        "published in SAML metadata — so this is not a secret being leaked.",
    )
    created_at: dt.datetime
    updated_at: dt.datetime

    assigned_groups: list[GroupRef]
    assigned_users: list[UserRef]


class ApplicationRegistration(BaseModel):
    """Register an application, or update one that already exists.

    The metadata document carries the entity id, the addresses and the certificate,
    so none of those are fields here. Letting somebody type them separately is how an
    assertion ends up posted to an address the application never published — see
    docs/adr/0006-paste-metadata-do-not-fetch-it.md.
    """

    slug: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
        description=(
            "Short name used in links, e.g. /idp/sso/expenses. Lowercase, digits "
            "and dashes, because it goes in a URL."
        ),
    )
    name: str = Field(min_length=1, max_length=255, description="What to call it in the console.")
    description: str | None = Field(default=None, max_length=500)
    metadata_xml: str = Field(
        min_length=1,
        description="The application's SAML metadata document, pasted in whole.",
    )
    enabled: bool = Field(
        default=True,
        description=(
            "Turn an application off to stop issuing logins for it without losing "
            "its settings or who had access."
        ),
    )
