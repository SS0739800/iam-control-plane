"""The apps we connect to, and who has access to them.

An app here is something that either trusts us to log people in or gets accounts
pushed to it by us (P6).

The SAML columns are load-bearing now. entity_id is what an AuthnRequest is matched
against, acs_url is where a signed assertion is posted, and slo_url is where a
logout confirmation goes — all in iam/routers/idp.py. They are filled in by reading
the application's own metadata rather than typed, because a mistyped acs_url is a
login delivered to the wrong address.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import AppProtocol, AppStatus, PrincipalType, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.group import Group
    from iam.models.user import User


class Application(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "applications"

    name: Mapped[str] = mapped_column(String(255), unique=True)
    slug: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        comment="Short name safe to put in a URL.",
    )
    description: Mapped[str | None] = mapped_column(String(500))

    protocol: Mapped[AppProtocol] = mapped_column(
        enum_type(AppProtocol),
        nullable=False,
        default=AppProtocol.SAML2,
    )
    status: Mapped[AppStatus] = mapped_column(
        enum_type(AppStatus),
        nullable=False,
        default=AppStatus.ACTIVE,
    )

    # ---------------------------------------------- SAML, read by iam/routers/idp.py
    entity_id: Mapped[str | None] = mapped_column(
        String(500),
        unique=True,
        comment="The app's SAML id. The spec says these are globally unique, so "
        "the unique constraint is just enforcing that.",
    )
    acs_url: Mapped[str | None] = mapped_column(
        String(500),
        comment="Where we send the login response after someone signs in.",
    )
    slo_url: Mapped[str | None] = mapped_column(String(500))
    nameid_format: Mapped[str | None] = mapped_column(String(200))
    signing_cert: Mapped[str | None] = mapped_column(
        Text,
        comment="The app's certificate, so we can check its requests are genuine.",
    )

    assignments: Mapped[list[AppAssignment]] = relationship(
        back_populates="application",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Application {self.slug} {self.protocol}>"


class AppAssignment(UUIDPrimaryKey, Timestamps, Base):
    """Gives one user, or one group, access to one app.

    There are two id columns and a rule saying exactly one must be filled in. The
    obvious alternative is a single "principal_id" plus a type column, but the
    database can't check a foreign key on that, so nothing stops it pointing at a
    row that no longer exists. Two columns means both cases stay checked.
    """

    __tablename__ = "app_assignments"

    application_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"),
        nullable=False,
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
    )

    role: Mapped[str | None] = mapped_column(
        String(64),
        comment="What role this gives them in that app, for example 'Employee'.",
    )

    application: Mapped[Application] = relationship(back_populates="assignments")
    user: Mapped[User | None] = relationship(back_populates="app_assignments")
    group: Mapped[Group | None] = relationship(back_populates="app_assignments")

    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL) <> (group_id IS NOT NULL)",
            name="exactly_one_principal",
        ),
        # These two work side by side because Postgres treats empty values as all
        # different from each other. So plenty of rows can have an empty user_id
        # without clashing, and the same the other way round.
        UniqueConstraint("application_id", "user_id", name="one_per_user"),
        UniqueConstraint("application_id", "group_id", name="one_per_group"),
        Index("ix_app_assignments_application_id", "application_id"),
        Index("ix_app_assignments_user_id", "user_id"),
        Index("ix_app_assignments_group_id", "group_id"),
    )

    @property
    def principal_type(self) -> PrincipalType:
        """Whether this row gives access to a person or to a group."""
        return PrincipalType.USER if self.user_id is not None else PrincipalType.GROUP

    @property
    def principal_id(self) -> uuid.UUID:
        """The id of whoever this gives access to, from whichever column has it."""
        principal = self.user_id if self.user_id is not None else self.group_id
        if principal is None:  # pragma: no cover - the CHECK constraint prevents this
            raise ValueError("app_assignment has neither user_id nor group_id")
        return principal
