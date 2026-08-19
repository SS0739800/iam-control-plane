"""Small shapes used in more than one place.

The Ref ones are so a user's page can list their groups and apps without dragging
in the whole group or app record each time. They hold what a link needs: an id, a
name, and whatever gets shown beside it.
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
        description=(
            "The group that gives them this access, or null if it was given to "
            "them directly. Answers 'why does this person have Salesforce?'"
        ),
    )


class SignedInUser(BaseModel):
    """Who the console is talking to, and what they can do.

    The permissions are sent as a list so the front end can hide buttons nobody
    can use. It is only ever a nicety: every one of them is checked again on the
    request, because a hidden button is not a permission check.
    """

    id: uuid.UUID
    user_name: str
    display_name: str
    role: PlatformRole
    permissions: list[str]
    via_saml_session: bool = Field(
        description=(
            "True when this came from a real login. False means the development "
            "stand-in identified the request, which never happens in production."
        )
    )


class DashboardCounts(BaseModel):
    """The numbers on the front page."""

    users: int
    active_users: int
    groups: int
    applications: int
    sso_applications: int = Field(
        description="How many of the apps use SAML login. Part of `applications`."
    )
    audit_events: int
