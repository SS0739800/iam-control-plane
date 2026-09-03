"""Shapes for granting and reading console roles."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import GrantSource, PlatformRole


class RoleGrantOut(BaseModel):
    """One decision to give somebody a role, live or long finished."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role: PlatformRole
    source: GrantSource
    reason: str | None

    granted_by_label: str = Field(
        description="Who granted it. A copy of their name, so it survives their own "
        "record being deleted."
    )
    created_at: dt.datetime = Field(description="When it was granted.")
    expires_at: dt.datetime | None

    revoked_at: dt.datetime | None
    revoked_by_label: str | None
    revoked_reason: str | None = Field(
        description="revoked, superseded, expired, user_deactivated, or somebody's own wording."
    )

    live: bool = Field(
        description="Whether this grant is giving them anything right now. False for "
        "anything revoked, superseded, or past its expiry."
    )


class RoleGrantCreate(BaseModel):
    """Give somebody a console role."""

    role: PlatformRole = Field(
        description="admin, helpdesk or auditor. Not employee — that is what "
        "somebody is with no grant, so revoke instead of granting it."
    )
    reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Why. Worth filling in: it is the part of an access review that "
        "cannot be reconstructed later.",
    )
    expires_at: dt.datetime | None = Field(
        default=None,
        description="When it should stop applying on its own. Strongly preferred for "
        "admin — standing access nobody revisits is how an unnoticed admin happens.",
    )


class RoleGrantRevoke(BaseModel):
    reason: str = Field(
        default="revoked",
        max_length=200,
        description="Why it was taken away, so a review can say.",
    )


class AccessSummary(BaseModel):
    """Everything one person has, and where it came from: what they can do
    here, what apps they can reach, and why.
    """

    user_id: uuid.UUID
    user_name: str
    display_name: str
    active: bool

    role: PlatformRole = Field(description="What they can do in this console right now.")
    role_granted_by: str | None = Field(
        default=None, description="Who gave them that, if it was granted rather than default."
    )
    role_granted_at: dt.datetime | None = None
    role_expires_at: dt.datetime | None = None

    groups: list[str] = Field(default_factory=list, description="Groups they are in.")
    grant_history: list[RoleGrantOut] = Field(
        default_factory=list, description="Every role they have ever had, newest first."
    )
