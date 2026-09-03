"""Rules that give people access because of who they are.

Handles joiners and movers automatically: e.g. someone joining Engineering
lands in the Engineering group with no one clicking anything, and leaving
it removes them.

Each rule is one condition, one group ("department is Engineering, so put
them in Engineering") rather than a boolean expression tree, since rules
are read (in audits) far more than they're written, and need to stay easy
to state correctly. Multiple rules can point at the same group.

ATTRIBUTES is a fixed allowlist of user columns a rule may reference, not
"any column" — otherwise a rule could read platform_role (letting group
membership depend on console privilege) or token_hash.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import RuleOperator, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.group import Group

ATTRIBUTES: dict[str, str] = {
    "department": "Department",
    "job_title": "Job title",
    "email": "Email address",
    "user_name": "Login name",
}
"""The user fields a rule is allowed to look at, and how to label them.

Adding an entry means group membership can now depend on that field, so
add deliberately.
"""

VALUELESS_OPERATORS = frozenset({RuleOperator.IS_SET, RuleOperator.IS_NOT_SET})
"""Operators that take no value. A rule using one ignores whatever is in `value`."""


class AccessRule(UUIDPrimaryKey, Timestamps, Base):
    """One condition, one group.

    Enabled rules run when a user is created and whenever the attribute
    they check changes. Disabling a rule keeps it (and its history) rather
    than deleting it, for questions like "did we used to grant this."
    """

    __tablename__ = "access_rules"

    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        comment="What this rule is for, in words. Shows up in the audit log.",
    )
    description: Mapped[str | None] = mapped_column(Text)

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="Turning a rule off takes back what it granted, on the next run.",
    )

    # ------------------------------------------------------------ the condition
    attribute: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Which user field to look at. Has to be one of rules.ATTRIBUTES.",
    )
    operator: Mapped[RuleOperator] = mapped_column(enum_type(RuleOperator), nullable=False)
    value: Mapped[str | None] = mapped_column(
        String(255),
        comment="What to compare against. Null for is_set and is_not_set.",
    )

    # ---------------------------------------------------------------- the grant
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        comment="The group people matching this rule go into.",
    )

    created_by_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Who wrote the rule. A copy of their name, so it survives "
        "their account being deleted.",
    )

    group: Mapped[Group] = relationship(back_populates="rules")

    @property
    def sentence(self) -> str:
        """The rule as a line of English, for the console and the audit log."""
        label = ATTRIBUTES.get(self.attribute, self.attribute)
        if self.operator == RuleOperator.IS_SET:
            return f"{label} has any value"
        if self.operator == RuleOperator.IS_NOT_SET:
            return f"{label} is empty"
        readable = {
            RuleOperator.EQUALS: "is",
            RuleOperator.NOT_EQUALS: "is not",
            RuleOperator.CONTAINS: "contains",
            RuleOperator.STARTS_WITH: "starts with",
        }[self.operator]
        return f"{label} {readable} {self.value!r}"

    __table_args__ = (
        # The same condition can't point at the same group twice.
        UniqueConstraint(
            "attribute", "operator", "value", "group_id", name="one_rule_per_condition_and_group"
        ),
        # The engine asks for enabled rules and nothing else, constantly.
        Index("ix_access_rules_enabled", "enabled", postgresql_where=text("enabled")),
        Index("ix_access_rules_group_id", "group_id"),
    )

    def __repr__(self) -> str:
        return f"<AccessRule {self.name!r} {self.sentence}>"
