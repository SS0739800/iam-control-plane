"""Who has been given what, and why.

Until now someone's console role was a column on their row, which answers "what
can this person do" and nothing else. It can't answer who decided that, when,
whether it was supposed to be temporary, or whether anyone ever took it away.
Those are the questions an access review is made of, so the grant becomes a row
of its own and the column becomes a cache of it.

One active grant per person, enforced by the database rather than by hope. See
the index at the bottom for why that constraint is the whole design.
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
    """Why a grant stopped applying. Recorded so a review can say which."""

    REVOKED = "revoked"
    """Somebody took it away on purpose."""

    SUPERSEDED = "superseded"
    """A different role was granted, replacing this one."""

    EXPIRED = "expired"
    """It had an end date and the date passed."""

    USER_DEACTIVATED = "user_deactivated"
    """They left. The leaver flow cut it."""


class RoleGrant(UUIDPrimaryKey, Timestamps, Base):
    """One decision to give one person a console role.

    Kept forever, revoked rather than deleted. "She was an admin for three weeks
    in March, granted by Priya for the migration, and it expired on its own" is
    exactly the sentence an access review needs to be able to produce, and
    deleting the row makes it unsayable.
    """

    __tablename__ = "role_grants"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    role: Mapped[PlatformRole] = mapped_column(
        enum_type(PlatformRole),
        nullable=False,
        comment="Never 'employee' — that's the absence of a grant, not a grant.",
    )

    source: Mapped[GrantSource] = mapped_column(
        enum_type(GrantSource),
        nullable=False,
        default=GrantSource.DIRECT,
        server_default=GrantSource.DIRECT.value,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        comment="Why they were given it. Free text, because the real reasons don't "
        "fit a dropdown.",
    )

    # ------------------------------------------------------------ who did it
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    granted_by_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Copy of the granter's name, kept because the id goes null if they "
        "are ever deleted and 'granted by nobody' is not an acceptable answer.",
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
        comment="One of RevokedGrantReason, or free text for a person's own wording.",
    )

    user: Mapped[User] = relationship(
        back_populates="role_grants",
        foreign_keys=[user_id],
    )

    def is_live(self, *, now: dt.datetime) -> bool:
        """Whether this grant is actually giving anybody anything right now."""
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)

    __table_args__ = (
        # At most one grant per person that hasn't been revoked. This is the
        # constraint the whole module is built around, and it is in the database
        # rather than in Python because two simultaneous grants would otherwise
        # race: both read "no existing grant", both insert, and the person now has
        # two roles with no defined winner.
        #
        # Expiry is deliberately not part of this. An expired grant still occupies
        # the slot until something revokes it with reason 'expired', which keeps
        # the invariant a plain "one unrevoked row" that the database can check.
        # Granting a new role supersedes whatever was there, expired or not, so
        # this never blocks a legitimate change.
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
