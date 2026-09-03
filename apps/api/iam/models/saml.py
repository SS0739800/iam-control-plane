"""Tables for logging people in with SAML.

Four things get stored:

identity_providers   who we accept logins from, and the key to check them with
saml_request_state   login requests we've sent out and are waiting on
saml_sessions        who's currently signed in
saml_assertion_seen  logins we've already accepted, so none can be reused
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.user import User


class IdentityProvider(UUIDPrimaryKey, Timestamps, Base):
    """Somewhere we accept logins from.

    Supports more than one provider (authentik, Okta, Entra) so we can test
    against all three and avoid depending on one vendor's quirks.
    """

    __tablename__ = "identity_providers"

    slug: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        comment="Short name used in the login URL, e.g. /saml/login?idp=authentik",
    )
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)

    entity_id: Mapped[str] = mapped_column(
        String(500),
        unique=True,
        comment="The provider's own id. Every login must say it came from this.",
    )
    sso_url: Mapped[str] = mapped_column(
        String(500),
        comment="Where we send people to log in.",
    )
    slo_url: Mapped[str | None] = mapped_column(
        String(500),
        comment="Where we send them to log out. Not all providers have one.",
    )

    signing_cert: Mapped[str] = mapped_column(
        Text,
        comment="The provider's certificate. A login is only trusted if it's "
        "signed with the matching key.",
    )

    want_signed_assertions: Mapped[bool] = mapped_column(
        default=True,
        comment="Require the assertion itself to be signed, not just the "
        "response wrapper (an unsigned assertion inside a signed wrapper "
        "could still be swapped). Turn off only if a provider can't sign it.",
    )

    def __repr__(self) -> str:
        return f"<IdentityProvider {self.slug}>"


class SamlRequestState(Base):
    """A login we've sent someone off to do, that we're waiting to hear back on.

    Kept in the database, not a cookie, because the provider answers via a
    cross-site form POST and browsers drop Lax cookies on those. See
    docs/adr/0003-single-origin.md. Looking the row up also gives replay
    protection: an answer matching no pending request is rejected.
    """

    __tablename__ = "saml_request_state"

    relay_state: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="Random token we send with the request and get handed back.",
    )

    request_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        comment="The id inside the login request we sent. The answer must "
        "quote it back to prove it's a response to us.",
    )

    idp_slug: Mapped[str] = mapped_column(String(64))

    return_to: Mapped[str] = mapped_column(
        String(500),
        default="/",
        comment="Where to send the person once they're in. Checked against "
        "an allowlist before use, to prevent an open redirect.",
    )

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Rows past this are dead: caps how late an answer can arrive "
        "and keeps this table from growing forever.",
    )

    __table_args__ = (Index("ix_saml_request_state_expires_at", "expires_at"),)

    def __repr__(self) -> str:
        return f"<SamlRequestState {self.relay_state[:8]}… for {self.idp_slug}>"


class SamlSession(Base):
    """Somebody who is currently signed in.

    Stored server-side rather than as a signed token, so a session can be
    revoked immediately (a token already handed out can't be taken back).
    The cookie holds a random value; this table stores only its hash, like
    a password, so reading this table alone doesn't let anyone sign in.
    """

    __tablename__ = "saml_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        comment="SHA-256 of the cookie value. The cookie itself is never stored.",
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    idp_slug: Mapped[str] = mapped_column(String(64))

    name_id: Mapped[str] = mapped_column(
        String(255),
        comment="How the provider identified this person in the login.",
    )
    name_id_format: Mapped[str | None] = mapped_column(String(200))

    session_index: Mapped[str | None] = mapped_column(
        String(255),
        comment="The provider's own name for this session, used to match a "
        "logout notification to it.",
    )

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="Set instead of deleting the row, to keep sign-out time on record.",
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(100))

    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))

    user: Mapped[User] = relationship()

    __table_args__ = (
        Index("ix_saml_sessions_user_id", "user_id"),
        Index("ix_saml_sessions_expires_at", "expires_at"),
        Index("ix_saml_sessions_session_index", "session_index"),
    )

    @property
    def is_live(self) -> bool:
        """Whether this session should still let someone through."""
        if self.revoked_at is not None:
            return False
        return self.expires_at > dt.datetime.now(dt.UTC)

    def __repr__(self) -> str:
        return f"<SamlSession {self.id} user={self.user_id}>"


class SamlAssertionSeen(Base):
    """A login we've already accepted.

    Each login carries a unique id; seeing it twice means the login response
    is being replayed, so the second one is rejected. Rows can be cleared
    once past not_on_or_after, since an expired login fails on timing anyway.
    """

    __tablename__ = "saml_assertion_seen"

    assertion_id: Mapped[str] = mapped_column(String(255), primary_key=True)

    issuer: Mapped[str] = mapped_column(String(500))

    not_on_or_after: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="When this login stops being valid, and so when we can forget it.",
    )
    seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        comment="Kept for the inspector: which session this became, who it was for.",
    )

    __table_args__ = (Index("ix_saml_assertion_seen_not_on_or_after", "not_on_or_after"),)

    def __repr__(self) -> str:
        return f"<SamlAssertionSeen {self.assertion_id[:16]}…>"
