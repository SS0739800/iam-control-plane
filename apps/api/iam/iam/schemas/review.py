"""Shapes for the access review."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    """One thing worth asking about."""

    kind: str = Field(description="Which check produced this, e.g. standing_privilege.")
    severity: str = Field(
        description="high — somebody has access they should not, now. medium — it is "
        "probably fine and nobody can prove it. low — worth tidying."
    )
    subject: str = Field(description="Who or what it is about.")
    subject_user_id: uuid.UUID | None = Field(
        description="The person, when it is about one, so the console can link to them."
    )
    concern: str = Field(description="Why this is a question, in a sentence.")
    suggested_action: str = Field(
        description="What to do about it. Every finding has one — a finding nobody can "
        "act on is a complaint, and after the second review nobody reads those."
    )
    since: dt.datetime | None = None


class AccessReviewOut(BaseModel):
    """One pass over the directory."""

    checked_at: dt.datetime
    clean: bool = Field(description="True when nothing turned up, which is the goal.")
    counts: dict[str, int]
    findings: list[FindingOut]
