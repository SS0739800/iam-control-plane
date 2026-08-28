"""Shapes for the systems we push accounts into.

The token appears in no response here, ever. It is stored encrypted rather than
hashed, so unlike the inbound tokens we genuinely could decrypt and return it — and
that is exactly why there is no field for it. A value that can be read back is a value
that leaks through a screenshot, a browser cache, or a log of the response. Changing a
token means sending a new one.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import LinkState


class ProvisioningTargetSummary(BaseModel):
    """A downstream system, and how the last push to it went."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    application_slug: str

    base_url: str
    enabled: bool

    address_concession: str | None = Field(
        description=(
            "A rule from ADR 0007 that was relaxed to allow this address — a private "
            "address, or plain HTTP. Shown so it reads as a decision somebody made "
            "rather than something nobody noticed."
        )
    )

    last_sync_at: dt.datetime | None
    last_sync_ok: bool | None = Field(
        description="Null means never attempted. The useful question is the negative "
        "one: a target that last succeeded three weeks ago is one nobody is watching."
    )
    last_error: str | None

    created_at: dt.datetime
    updated_at: dt.datetime

    # ------------------------------------------------------------ the numbers
    accounts_active: int = Field(description="People with a live account downstream.")
    accounts_pending: int = Field(description="People who should have an account and do not yet.")
    accounts_failed: int = Field(description="Pushes that did not work.")
    accounts_orphaned: int = Field(
        description=(
            "People we tried to remove and could not. They still have access "
            "downstream, which is the number on this page that most needs acting on."
        )
    )
    accounts_deprovisioned: int

    accounts_waiting_to_push: int = Field(
        description=(
            "People a sync would touch right now — changed since the last push, newly "
            "entitled, or no longer entitled and still switched on downstream. Nothing "
            "pushes on its own, so this is the difference between what we know and what "
            "the downstream has been told."
        )
    )


class ProvisioningTargetCreate(BaseModel):
    """Register a downstream system."""

    # Extras are refused rather than ignored, which matters more here than it looks.
    # push_groups used to live on this model and did nothing; a client still sending it
    # would otherwise get a 200 and reasonably believe groups were flowing. A 422
    # naming the field it does not know is the honest answer.
    model_config = ConfigDict(extra="forbid")

    application_id: uuid.UUID = Field(
        description=(
            "Which application this provisions. Who gets pushed is whoever has access "
            "to it — there is no separate list to keep in step."
        )
    )
    base_url: str = Field(
        min_length=1,
        max_length=500,
        description="Its SCIM root, e.g. https://example.test/scim/v2.",
    )
    token: str = Field(
        min_length=1,
        description=(
            "The bearer token it issued us. Stored encrypted and never returned by " "any endpoint."
        ),
    )
    enabled: bool = True


class ProvisioningTargetUpdate(BaseModel):
    """Change a target. Anything left out stays as it is."""

    model_config = ConfigDict(extra="forbid")

    base_url: str | None = Field(default=None, min_length=1, max_length=500)
    token: str | None = Field(
        default=None,
        min_length=1,
        description="A replacement token. Send this to rotate; there is no way to read "
        "the current one.",
    )
    enabled: bool | None = None


class ProvisioningLinkOut(BaseModel):
    """One person, as an account in one downstream."""

    user_id: uuid.UUID
    user_name: str
    display_name: str
    active: bool = Field(description="Whether they are active in *our* directory.")

    remote_id: str | None = Field(
        description="The id the downstream gave their account. Null means no account "
        "exists there yet."
    )
    state: LinkState
    last_pushed_at: dt.datetime | None
    last_error: str | None
    attempts: int


class SyncResult(BaseModel):
    """What one run did."""

    correlation_id: uuid.UUID = Field(
        description="Every audit entry this run wrote carries it, so the whole cascade "
        "can be read back as one story."
    )
    created: int
    adopted: int = Field(
        description="Accounts that already existed downstream and were linked rather "
        "than created. Onboarding rather than provisioning."
    )
    updated: int
    deactivated: int
    reactivated: int
    unchanged: int
    failed: int
    skipped_exhausted: int = Field(
        description="Links that have failed too many times to keep retrying "
        "automatically. A forced sync picks them up."
    )
    stopped_early: str | None = Field(
        description="Why the run gave up, if it did. Usually a rejected token, which "
        "would fail identically for everybody remaining."
    )
    ok: bool


class ProbeResult(BaseModel):
    """Whether a target answers and accepts our token, without changing anything."""

    reachable: bool
    detail: str = Field(description="What the target said, or why we could not reach it.")
