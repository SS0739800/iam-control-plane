"""Groups, and who's in them.

Membership is its own class, not a plain link table, so we can record when
someone joined (access reviews need to ask how long they've had it).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import IdentitySource, MembershipSource, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.application import AppAssignment
    from iam.models.rules import AccessRule
    from iam.models.user import User


class Group(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "groups"

    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str | None] = mapped_column(String(500))

    external_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        comment="The id the identity provider uses for this group.",
    )

    source: Mapped[IdentitySource] = mapped_column(
        enum_type(IdentitySource),
        nullable=False,
        default=IdentitySource.MANUAL,
    )

    hrms_role: Mapped[str | None] = mapped_column(
        String(64),
        comment="The HRMS role membership in this group grants. Set on the "
        "group, not per person.",
    )

    member_links: Mapped[list[GroupMember]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
    )
    rules: Mapped[list[AccessRule]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
    )
    members: Mapped[list[User]] = relationship(
        secondary="group_members",
        viewonly=True,
        order_by="User.display_name",
    )

    app_assignments: Mapped[list[AppAssignment]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Group {self.name}>"


class GroupMember(Base):
    """One person being in one group, and why.

    The `source` column lets an access rule remove only the memberships it
    granted, not ones added by the provider or a person. See MembershipSource.
    """

    __tablename__ = "group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )

    source: Mapped[MembershipSource] = mapped_column(
        enum_type(MembershipSource),
        nullable=False,
        default=MembershipSource.MANUAL,
        server_default=MembershipSource.MANUAL.value,
        comment="Why they are in this group. Only 'rule' rows are removed by " "the rule engine.",
    )

    added_by_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("access_rules.id", ondelete="SET NULL"),
        comment="Which rule put them here, when source is 'rule'. Goes null "
        "if the rule is deleted, leaving the membership in place.",
    )

    # No updated_at: membership is either there or not, nothing to edit.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    group: Mapped[Group] = relationship(back_populates="member_links")
    user: Mapped[User] = relationship(back_populates="group_links")

    __table_args__ = (
        # The primary key covers "who's in this group"; this covers the
        # reverse lookup, "what groups is this user in".
        Index("ix_group_members_user_id", "user_id"),
        # Lets the rule engine find one user's rule-granted memberships
        # without scanning all of their memberships.
        Index("ix_group_members_user_source", "user_id", "source"),
    )

    def __repr__(self) -> str:
        return f"<GroupMember group={self.group_id} user={self.user_id}>"
