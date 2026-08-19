"""Shapes for reading and writing access rules."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field

from iam.models.enums import RuleOperator


class RuleAttribute(BaseModel):
    """One field a rule is allowed to look at."""

    name: str
    label: str


class AccessRuleOut(BaseModel):
    """A rule, with the sentence it reads as."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    enabled: bool

    attribute: str
    operator: RuleOperator
    value: str | None

    group_id: uuid.UUID
    group_name: str

    sentence: str = Field(
        description="The condition in words, e.g. \"Department is 'Engineering'\". "
        "The console shows this rather than the three fields, because a rule that "
        "can't be read out loud can't be reviewed."
    )
    member_count: int = Field(
        description="How many people are in the group because of a rule right now."
    )

    created_by_label: str
    created_at: dt.datetime
    updated_at: dt.datetime


class AccessRuleCreate(BaseModel):
    """Write a new rule."""

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    attribute: str = Field(description="One of the names from GET /api/access-rules/attributes.")
    operator: RuleOperator
    value: str | None = Field(
        default=None,
        max_length=255,
        description="Leave empty for is_set and is_not_set; required for everything else.",
    )
    group_id: uuid.UUID = Field(description="The group people matching this rule go into.")
    enabled: bool = Field(
        default=True,
        description="A rule created switched off grants nothing until it is enabled.",
    )


class AccessRuleUpdate(BaseModel):
    """Change a rule. Anything left out stays as it is."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    attribute: str | None = None
    operator: RuleOperator | None = None
    value: str | None = Field(default=None, max_length=255)
    group_id: uuid.UUID | None = None


class AffectedPerson(BaseModel):
    """Somebody a rule applies to."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_name: str
    display_name: str
    department: str | None
    job_title: str | None


class RulePreview(BaseModel):
    """Who a rule would affect, before anybody commits to it.

    The difference between writing a rule confidently and writing one and hoping.
    A condition that reads correctly and matches four hundred people usually means
    the value was mistyped, and this is where that gets noticed.
    """

    sentence: str
    group_name: str
    matches: int
    already_in_group: int = Field(
        description="Of those, how many are in the group already — so the rule would "
        "change nothing for them."
    )
    would_be_added: int
    sample: list[AffectedPerson] = Field(
        description="A few of the people who match, to eyeball. Not the whole list."
    )


class RuleRunResult(BaseModel):
    """What happened when a rule was applied to everybody."""

    added: list[str]
    removed: list[str]
    unchanged: bool
