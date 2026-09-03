"""Audit entries and the tamper check, as the API sends them.

Hashes are included because they aren't secret, they're the proof the log
is intact.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import ActorType, AuditOutcome


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: dt.datetime

    actor_type: ActorType
    actor_id: uuid.UUID | None
    actor_label: str

    action: str
    outcome: AuditOutcome

    target_type: str | None
    target_id: str | None
    target_label: str | None

    ip_address: str | None
    correlation_id: uuid.UUID | None
    detail: dict[str, Any]

    prev_hash: str
    hash: str


class ChainVerification(BaseModel):
    """What the tamper check found."""

    valid: bool
    events_checked: int
    broken_at_id: int | None = Field(
        default=None,
        description="The first entry that didn't add up, if there was one.",
    )
    reason: str | None = Field(
        default=None,
        description="What was wrong with it.",
    )
