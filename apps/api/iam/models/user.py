"""A person, and what they're allowed to do in this console.

The field names match what SCIM calls things (userName, externalId, active,
employeeNumber) instead of picking our own words for them. P3 has to hand these
straight back over SCIM, and renaming everything at that point would mean
touching every file.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import IdentitySource, PlatformRole, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.application import AppAssignment
    from iam.models.group import Group, GroupMember


class User(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "users"

    # --------------------------------------------------------------- identity
    external_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        comment="The id the identity provider uses for this person.",
    )

    user_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        comment="What they log in with, usually their email. Doesn't change.",
    )

    email: Mapped[str] = mapped_column(String(320))

    given_name: Mapped[str | None] = mapped_column(String(128))
    family_name: Mapped[str | None] = mapped_column(String(128))
    display_name: Mapped[str] = mapped_column(String(255))

    # ---------------------------------------------------------------- status
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="Switching this off is how we remove someone. We never delete the "
        "row, so you can still see what they had access to after they've left.",
    )

    # -------------------------------------------------------------- employment
    employee_number: Mapped[str | None] = mapped_column(String(64))
    department: Mapped[str | None] = mapped_column(String(128))
    job_title: Mapped[str | None] = mapped_column(String(128))

    manager_id: Mapped[uuid.UUID | None] = mapped_column(
        # SET NULL, not CASCADE. If a manager's row ever goes, their team should
        # just lose the link, not get deleted along with them.
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    # ---------------------------------------------------------- authorization
    platform_role: Mapped[PlatformRole] = mapped_column(
        enum_type(PlatformRole),
        nullable=False,
        default=PlatformRole.EMPLOYEE,
        server_default=PlatformRole.EMPLOYEE.value,
        comment="What this person can do in the console. In P4 this gets worked "
        "out from their access grants instead of being stored here.",
    )

    source: Mapped[IdentitySource] = mapped_column(
        enum_type(IdentitySource),
        nullable=False,
        default=IdentitySource.MANUAL,
        comment="Where this record came from. If SCIM created it, editing it here "
        "gets overwritten on the next sync, so the API refuses those edits.",
    )

    # ------------------------------------------------------------ relationships
    manager: Mapped[User | None] = relationship(
        remote_side="User.id",
        back_populates="reports",
    )
    reports: Mapped[list[User]] = relationship(
        back_populates="manager",
        cascade="save-update",
    )

    group_links: Mapped[list[GroupMember]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Shortcut for reading someone's groups without going through GroupMember.
    # viewonly stops SQLAlchemy complaining about two ways to write the same rows.
    groups: Mapped[list[Group]] = relationship(
        secondary="group_members",
        viewonly=True,
        order_by="Group.name",
    )

    app_assignments: Mapped[list[AppAssignment]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        # The user list filters on these all the time. With 1,284 users, scanning
        # the whole table is already slow enough to notice.
        Index("ix_users_active", "active"),
        Index("ix_users_department", "department"),
        Index("ix_users_manager_id", "manager_id"),
        Index("ix_users_display_name", "display_name"),
    )

    def __repr__(self) -> str:
        return f"<User {self.user_name} active={self.active}>"
