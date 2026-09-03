"""Who has been given a console role, by whom, and when.

Each grant is its own row (who granted it, when, whether it expired or was
revoked) instead of just a role column on the user. A user can have at most
one active grant, enforced by the unique index at the bottom.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import GrantSource, PlatformRole, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.user import User


class RevokedGrantReason:
    """Why a grant stopped applying."""

    REVOKED = "revoked"
    """Someone took it away."""

    SUPERSEDED = "superseded"
    """A different role was granted, replacing this one."""

    EXPIRED = "expired"
    """It had an end date and the date passed."""

    USER_DEACTIVATED = "user_deactivated"
    """They left, and the leaver flow cut it."""


class RoleGrant(UUIDPrimaryKey, Timestamps, Base):
    """One decision to give one person a console role.

    Rows are kept and revoked, never deleted, so an access review can see
    full history (who granted what, when, and why it ended).
    """

    __tablename__ = "role_grants"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    role: Mapped[PlatformRole] = mapped_column(
        enum_type(PlatformRole),
        nullable=False,
        comment="Never 'employee'. That role means no grant, not a grant of it.",
    )

    source: Mapped[GrantSource] = mapped_column(
        enum_type(GrantSource),
        nullable=False,
        default=GrantSource.DIRECT,
        server_default=GrantSource.DIRECT.value,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        comment="Why they were given it. Free text.",
    )

    # ------------------------------------------------------------ who did it
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    granted_by_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Copy of the granter's name. Kept even if the granter is later "
        "deleted, since granted_by_id would go null.",
    )

    expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="When it stops applying on its own. Null means indefinite.",
    )

    # ---------------------------------------------------------- taking it away
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    revoked_by_label: Mapped[str | None] = mapped_column(String(255))
    revoked_reason: Mapped[str | None] = mapped_column(
        String(200),
        comment="One of RevokedGrantReason, or free text.",
    )

    user: Mapped[User] = relationship(
        back_populates="role_grants",
        foreign_keys=[user_id],
    )

    def is_live(self, *, now: dt.datetime) -> bool:
        """Whether this grant is currently in effect."""
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)

    __table_args__ = (
        # At most one unrevoked grant per user. Enforced in the database so two
        # concurrent grants can't both succeed and leave two "active" roles.
        # An expired grant still counts as unrevoked until something revokes it
        # with reason 'expired' — granting a new role supersedes it either way.
        Index(
            "one_live_role_grant_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        # Access reviews read a person's whole history, newest first.
        Index("ix_role_grants_user_granted", "user_id", "created_at"),
        # The expiry sweep asks for grants due to end, across everybody.
        Index(
            "ix_role_grants_expiring",
            "expires_at",
            postgresql_where=text("revoked_at IS NULL AND expires_at IS NOT NULL"),
        ),
    )

    def __repr__(self) -> str:
        state = "live" if self.revoked_at is None else f"revoked:{self.revoked_reason}"
        return f"<RoleGrant {self.role} user={self.user_id} {state}>"
