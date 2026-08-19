"""Rules that give people access because of who they are.

The joiner and mover half of the lifecycle. Somebody arrives in Engineering and
lands in the Engineering group without anybody clicking anything; somebody moves
to Sales and stops being in it.

One comparison per rule, deliberately
-------------------------------------

A rule is a single readable sentence: "department is Engineering, so put them in
Engineering". Not a boolean expression tree, not a small language.

The temptation is real — dynamic group syntax in the commercial products lets you
write nested conditions — and the reason to resist it is that access rules are
read far more often than they are written. Somebody in an audit has to say what
this rule does and be right. Two rules pointing at the same group compose
perfectly well and each one still reads as a sentence.

Attributes are a fixed list
---------------------------

``ATTRIBUTES`` names the columns a rule may look at. It is not "any column on the
user", because a rule reading ``platform_role`` would let group membership depend
on console privilege, which is backwards and circular — and one reading
``token_hash`` should be unthinkable rather than merely unlikely.
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

Add to this only on purpose. Every entry is a thing group membership can now
depend on, and some columns on the user table have no business being one.
"""

VALUELESS_OPERATORS = frozenset({RuleOperator.IS_SET, RuleOperator.IS_NOT_SET})
"""Operators that take no value. A rule using one ignores whatever is in `value`."""


class AccessRule(UUIDPrimaryKey, Timestamps, Base):
    """One condition, one group.

    Enabled rules run when somebody is created and whenever the attributes they
    look at change. A disabled rule is left in place with its history rather than
    deleted, because "we used to give everybody in Sales the CRM" is a question
    that gets asked.
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
        comment="Who wrote the rule. A copy of their name, so it survives their "
        "record being deleted.",
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
        # The same condition twice pointing at the same group is a duplicate, and
        # two rules that disagree about one group would just both add them.
        UniqueConstraint(
            "attribute", "operator", "value", "group_id", name="one_rule_per_condition_and_group"
        ),
        # The engine asks for enabled rules and nothing else, constantly.
        Index("ix_access_rules_enabled", "enabled", postgresql_where=text("enabled")),
        Index("ix_access_rules_group_id", "group_id"),
    )

    def __repr__(self) -> str:
        return f"<AccessRule {self.name!r} {self.sentence}>"
