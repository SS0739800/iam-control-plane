"""Small shapes used in more than one place.

The Ref ones let a user's page list their groups and apps without loading
the full group or app record: just an id, a name, and a bit of context.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import AppProtocol, PlatformRole


class UserRef(BaseModel):
    """Just enough of a user to link to them."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_name: str
    display_name: str
    active: bool


class GroupRef(BaseModel):
    """Just enough of a group to link to it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    hrms_role: str | None = None


class AppRef(BaseModel):
    """An app someone can get into, and what role it gives them."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    protocol: AppProtocol
    role: str | None = Field(
        default=None,
        description="What role this access gives them inside the app.",
    )
    via_group: str | None = Field(
        default=None,
        description="The group that gives them this access, or null if given directly.",
    )


class SignedInUser(BaseModel):
    """Who the console is talking to, and what they can do.

    Permissions are a list so the front end can hide buttons the user can't
    use. That's just UI convenience; every action is checked again server-side.
    """

    id: uuid.UUID
    user_name: str
    display_name: str
    role: PlatformRole
    permissions: list[str]
    via_saml_session: bool = Field(
        description="True for a real login. False means the dev stand-in "
        "identified the request (never true in production)."
    )


class DashboardCounts(BaseModel):
    """The numbers on the front page."""

    users: int
    active_users: int
    groups: int
    applications: int
    sso_applications: int = Field(
        description="How many applications use SAML login. A subset of `applications`."
    )
    audit_events: int
    live_admins: int = Field(
        description="Active people who currently hold an admin grant. Zero "
        "means nobody can administer this deployment except via shell access."
    )
