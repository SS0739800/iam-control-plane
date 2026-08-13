"""Groups, and who's in them.

Membership is its own class rather than a plain link table so we can store when
someone joined. The access reviews in P4 need to ask how long someone has had
something.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import IdentitySource, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.application import AppAssignment
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
        comment="What role being in this group gives you in the HRMS. Set on the "
        "group, not per person, so you manage access by changing membership.",
    )

    member_links: Mapped[list[GroupMember]] = relationship(
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
    """One person being in one group."""

    __tablename__ = "group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # No updated_at. You're either in a group or you're not; there's nothing here
    # to edit.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    group: Mapped[Group] = relationship(back_populates="member_links")
    user: Mapped[User] = relationship(back_populates="group_links")

    __table_args__ = (
        # The primary key already answers "who's in this group". This index answers
        # the other way round, "what groups is this person in", which the user page
        # asks every time it loads.
        Index("ix_group_members_user_id", "user_id"),
    )

    def __repr__(self) -> str:
        return f"<GroupMember group={self.group_id} user={self.user_id}>"
