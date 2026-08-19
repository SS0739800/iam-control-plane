"""Which applications we have signed somebody into.

This table is what makes single logout possible, and its absence is what made it
impossible before.

Every assertion we issue carries a SessionIndex — our name for that login. When an
application later says "sign this person out", it quotes that index back at us. If
we never wrote it down, there is nothing to match the request against, and the only
honest answer to a logout request is a shrug. So the index is stored here, next to
the browser session it belongs to and the application it was issued for.

One row per application per browser session
-------------------------------------------

Signing in to three applications from one browser makes three rows sharing one
``saml_session_id``. That shape is deliberate: it is what lets a logout arriving
from any one of them be traced back to the browser session, and it is what a
fan-out to the other two would read.

Kept after the session ends, like everything else here. "They were signed in to the
finance system that afternoon" is a question somebody asks after an incident, and it
is unanswerable if the row is deleted when they log out.
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
        comment="The browser session this login came from. Goes null rather than "
        "cascading, because the record of having signed in should outlive the "
        "session that did it.",
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
        comment="Our name for this login, as it appeared in the assertion. What an "
        "application quotes back when it asks us to sign the person out.",
    )
    name_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="The subject we told the application about. A logout request may "
        "name this instead of the session index, so both are searchable.",
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
        # The index we issued has to be unique, or a logout request quoting one
        # would be ambiguous about which login it meant.
        UniqueConstraint("session_index", name="one_login_per_session_index"),
        # How a logout request is resolved: by the index it quotes.
        Index("ix_idp_sessions_session_index", "session_index"),
        # The fallback lookup, for a request that names the subject instead.
        Index("ix_idp_sessions_name_id", "name_id"),
        # Everything one browser session opened, which is what a fan-out reads.
        Index("ix_idp_sessions_saml_session", "saml_session_id"),
        # "Who is signed in to the finance system right now."
        Index("ix_idp_sessions_application", "application_id", "ended_at"),
    )

    def __repr__(self) -> str:
        state = "live" if self.is_live else f"ended:{self.ended_reason}"
        return f"<IdpSession app={self.application_id} {state}>"
