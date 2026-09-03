"""Who is allowed to push accounts at us over SCIM.

One row per system allowed to write to the directory. Kept separate from
identity_providers, even when the same system (e.g. authentik) fills both
roles, since signing people in and creating/deactivating accounts are
different powers — separating them lets either be turned off independently
and lets the audit log say which one did something.

The token works like the session cookie: the client gets a long random
string once, and we store only its hash. See iam/tokens.py.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from iam.models.base import Base
from iam.models.mixins import Timestamps, UUIDPrimaryKey


class ScimClient(UUIDPrimaryKey, Timestamps, Base):
    """A system we accept SCIM writes from."""

    __tablename__ = "scim_clients"

    name: Mapped[str] = mapped_column(
        String(255),
        comment="What to call it in the console, e.g. 'authentik (local)'.",
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        comment="SHA-256 of the bearer token. Shown once at creation, never "
        "stored in full.",
    )

    enabled: Mapped[bool] = mapped_column(
        default=True,
        comment="Turning this off stops the sync but keeps the record, which "
        "the audit log still refers to.",
    )

    description: Mapped[str | None] = mapped_column(
        String(500),
        comment="Why this exists, for whoever finds it in six months.",
    )

    last_used_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="When this token was last accepted. Flags tokens unused for "
        "months, which is a sign nobody would notice if it were stolen.",
    )

    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="Set instead of deleting the row, so it stays clear the sync "
        "stopped because the token was revoked.",
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(200))

    # No separate index on token_hash: the unique constraint above already
    # creates one, and every lookup goes through it.

    @property
    def is_usable(self) -> bool:
        """Whether this token should still be accepted."""
        return self.enabled and self.revoked_at is None

    def __repr__(self) -> str:
        return f"<ScimClient {self.name} enabled={self.enabled}>"
