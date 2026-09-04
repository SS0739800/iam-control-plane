"""Users, groups and apps, as the API sends them.

Two shapes each: a Summary for lists and a Detail for a single record, so
the list query doesn't have to join membership and access tables it won't show.
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
        description="Everything they can get into: direct grants plus "
        "anything from a group they're in."
    )


class UserUpdate(BaseModel):
    """The fields you're allowed to change. A field left out stays as is.

    Login name, email, and external id come from the identity provider for
    SCIM-created users, so editing them here would just be undone by the
    next sync.
    """

    model_config = ConfigDict(extra="forbid")

    active: bool | None = None
    department: str | None = None
    job_title: str | None = None

    # platform_role is not editable here. It used to be, which let helpdesk
    # (who has users:write) grant themselves admin without roles:write, and
    # would set the cached role with no grant behind it. Roles are granted
    # only at POST /api/users/{id}/role-grants.


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
        description="First page of members only. Use /api/groups/{id}/members "
        "to page through a big group."
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

    The SAML fields are shown, not hidden, because iam/routers/idp.py reads
    them to answer logins, and a mistyped entity id is easier to spot here
    than in the database.
    """

    entity_id: str | None
    acs_url: str | None
    slo_url: str | None
    nameid_format: str | None
    signing_cert: str | None = Field(
        default=None,
        description="The SP's public certificate, from its SAML metadata. Not a secret.",
    )
    created_at: dt.datetime
    updated_at: dt.datetime

    assigned_groups: list[GroupRef]
    assigned_users: list[UserRef]


class ApplicationRegistration(BaseModel):
    """Register an application, or update one that already exists.

    Entity id, addresses, and certificate come from the pasted metadata
    document rather than being typed separately, since a typed address
    could be wrong in a way that misdirects an assertion. See
    docs/adr/0006-paste-metadata.md.
    """

    slug: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
        description="Short name used in links, e.g. /idp/sso/expenses. "
        "Lowercase, digits, and dashes only.",
    )
    name: str = Field(min_length=1, max_length=255, description="What to call it in the console.")
    description: str | None = Field(default=None, max_length=500)
    metadata_xml: str = Field(
        min_length=1,
        description="The application's SAML metadata document, pasted in whole.",
    )
    enabled: bool = Field(
        default=True,
        description="Turn off to stop issuing logins without losing settings " "or access history.",
    )
