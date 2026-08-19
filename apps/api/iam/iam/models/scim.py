"""Who is allowed to push accounts at us over SCIM.

One row per system we let write to the directory. In practice that is authentik
to begin with, and later whatever else runs provisioning.

This is a separate table from identity_providers on purpose, even though the
same authentik fills both roles. Signing people in and writing to the directory
are different powers with different blast radii: a SAML provider can say who
somebody is at the moment they log in, while a SCIM client can create and
deactivate anybody at any time, whether or not they ever visit. Keeping them
apart means either can be turned off without touching the other, and the audit
log can say which one did something.

The token works the way the session cookie does: the client is handed a long
random string once, and we keep only its hash. See iam/tokens.py.
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
        comment="SHA-256 of the bearer token. The token itself is shown once, when "
        "it is created, and never stored.",
    )

    enabled: Mapped[bool] = mapped_column(
        default=True,
        comment="Turning this off stops the sync without deleting the record of it "
        "having existed, which the audit log still refers to.",
    )

    description: Mapped[str | None] = mapped_column(
        String(500),
        comment="Why this exists, for whoever finds it in six months.",
    )

    last_used_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="When this token was last accepted. The useful question is the "
        "opposite one: a token that has not been used in months is one nobody "
        "would notice being stolen.",
    )

    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="Set instead of deleting the row, so 'that sync stopped on the 3rd, "
        "because we revoked it' stays answerable.",
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
