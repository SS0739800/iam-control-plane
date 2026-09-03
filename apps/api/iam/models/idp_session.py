"""Which applications we have signed somebody into.

This is what makes single logout possible. Every assertion we issue carries
a SessionIndex, and when an application asks us to sign someone out, it
quotes that index back — we need it stored to match the request against.

One browser session that signs in to three apps makes three rows sharing
one saml_session_id, so a logout from any one of them can be traced back
to the others. Rows are kept after the session ends, so "were they signed
into finance that afternoon" can still be answered later.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.mixins import UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.application import Application
    from iam.models.saml import SamlSession
    from iam.models.user import User


class IdpSession(UUIDPrimaryKey, Base):
    """One application, signed into once, from one browser session."""

    __tablename__ = "idp_sessions"

    saml_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("saml_sessions.id", ondelete="SET NULL"),
        comment="The browser session this login came from. Goes null instead "
        "of cascading, so this record outlives the session.",
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"),
        nullable=False,
    )

    session_index: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Our name for this login, from the assertion. An application "
        "quotes this back when asking us to sign someone out.",
    )
    name_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="The subject we told the application about. A logout request "
        "may name this instead of the session index, so both are searchable.",
    )

    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    ended_reason: Mapped[str | None] = mapped_column(String(100))

    saml_session: Mapped[SamlSession | None] = relationship()
    user: Mapped[User] = relationship()
    application: Mapped[Application] = relationship()

    @property
    def is_live(self) -> bool:
        return self.ended_at is None

    __table_args__ = (
        # Must be unique, or a logout request quoting it would be ambiguous.
        UniqueConstraint("session_index", name="one_login_per_session_index"),
        # Resolves a logout request by the index it quotes.
        Index("ix_idp_sessions_session_index", "session_index"),
        # Fallback lookup, for a request that names the subject instead.
        Index("ix_idp_sessions_name_id", "name_id"),
        # Everything one browser session opened, for single-logout fan-out.
        Index("ix_idp_sessions_saml_session", "saml_session_id"),
        # "Who is signed in to this application right now."
        Index("ix_idp_sessions_application", "application_id", "ended_at"),
    )

    def __repr__(self) -> str:
        state = "live" if self.is_live else f"ended:{self.ended_reason}"
        return f"<IdpSession app={self.application_id} {state}>"
