"""Shapes for managing the systems that provision into us.

The token appears in exactly one response - the one that creates it. There's
no field anywhere else that could carry it back, since we store only its
hash. A "show token" button would either lie or mean we'd kept it.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field


class ScimClientSummary(BaseModel):
    """A system we accept directory writes from."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    enabled: bool
    created_at: dt.datetime
    last_used_at: dt.datetime | None = Field(
        description=(
            "When this token was last accepted. A token unused for months is "
            "one nobody would notice being stolen."
        )
    )
    revoked_at: dt.datetime | None
    revoked_reason: str | None

    usable: bool = Field(
        description="Whether this token would be accepted right now - enabled and not revoked."
    )


class ScimClientCreate(BaseModel):
    """Ask for a new token."""

    name: str = Field(
        min_length=1,
        max_length=255,
        description="What to call it, e.g. 'authentik (local)'. Has to be unique so "
        "the audit log is unambiguous about which system acted.",
    )
    description: str | None = Field(
        default=None,
        max_length=500,
        description="Why it exists, for whoever finds it in six months.",
    )


class ScimClientIssued(ScimClientSummary):
    """A newly created client, with its token.

    The only response that ever carries a token. Store it now - there's no
    way to read it again, since we kept only the hash.
    """

    token: str = Field(
        description=(
            "The bearer token. Shown once. Give it to the provider as "
            "Authorization: Bearer <token>."
        )
    )


class ScimClientRevoke(BaseModel):
    reason: str = Field(
        default="revoked from the console",
        max_length=200,
        description="Why, so the audit log can say.",
    )


class ProvisioningActivity(BaseModel):
    """One thing a provisioning system did to the directory."""

    id: int
    occurred_at: dt.datetime
    action: str
    client: str | None = Field(description="Which SCIM client did it.")
    target: str | None = Field(description="Who or what it was done to.")
    outcome: str
    summary: str | None = Field(default=None, description="What changed, in words, when we know.")


class ProvisioningOverview(BaseModel):
    """What provisioning has actually done to this directory.

    Counts, not a list - the answer people want here is "is the sync working
    and what does it own", not a directory listing they can get from the
    Users page.
    """

    users_from_scim: int = Field(description="People the provider created or now manages.")
    groups_from_scim: int
    users_from_login: int = Field(
        description=(
            "People who arrived by logging in rather than being provisioned. "
            "A healthy sync keeps this number small."
        )
    )
    active_clients: int
    last_sync_at: dt.datetime | None = Field(
        default=None, description="The most recent time any provisioning client wrote anything."
    )
