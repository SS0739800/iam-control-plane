"""Shapes for access requests."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import RequestState


class AccessRequestOut(BaseModel):
    """One request, and what happened to it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    state: RequestState

    requester_id: uuid.UUID
    requester_label: str
    group_id: uuid.UUID
    group_label: str
    reason: str

    decided_by_label: str | None
    decided_at: dt.datetime | None
    decision_note: str | None
    expires_at: dt.datetime | None

    created_at: dt.datetime
    is_open: bool


class AccessRequestCreate(BaseModel):
    """Ask to be put in a group."""

    group_id: uuid.UUID
    reason: str = Field(
        min_length=1,
        max_length=2000,
        description="Why the access is needed. Required — an approver with no reason "
        "in front of them is rubber-stamping rather than deciding.",
    )


class Decision(BaseModel):
    """An approver's answer."""

    note: str | None = Field(
        default=None,
        max_length=2000,
        description="What you decided and why. The most useful field here during a "
        "review, and the one most likely to be left empty.",
    )
    expires_at: dt.datetime | None = Field(
        default=None,
        description="Approvals only. When the access should end. 'Until the end of "
        "the quarter' is the usual honest answer to an access request.",
    )
