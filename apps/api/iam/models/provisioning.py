"""The systems we push accounts into, and what we pushed where.

Who gets provisioned to a target is just whoever has access to its
application, from the same app_assignments rows that decide login access.
There's no separate list to keep in sync.

ProvisioningLink stores the downstream's own id for each account, so a
later update or deactivation can address it directly instead of searching
by username (which breaks if the username changed, e.g. mid-leaver).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import LinkState, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.application import Application
    from iam.models.user import User


class ProvisioningTarget(UUIDPrimaryKey, Timestamps, Base):
    """One downstream system we push accounts into."""

    __tablename__ = "provisioning_targets"

    application_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        comment="Which application this provisions. One target per "
        "application, so two syncs can't race writing the same accounts.",
    )

    base_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="The downstream's SCIM root, e.g. https://example/scim/v2. "
        "Checked against ADR 0007 when set, not on every push.",
    )

    token_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="The bearer token, encrypted (not hashed, unlike inbound "
        "tokens — see iam/secrets.py).",
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="Turning a target off stops pushes without losing the links, "
        "so turning it back on doesn't recreate every account.",
    )

    address_concession: Mapped[str | None] = mapped_column(
        String(255),
        comment="An ADR 0007 rule relaxed to allow this address (private, "
        "or plain HTTP). Stored so the page shows it as a decision, not an "
        "oversight.",
    )

    # ------------------------------------------------------ how it last went
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_ok: Mapped[bool | None] = mapped_column(
        Boolean,
        comment="Null means never tried. Flags targets nobody's watching, "
        "e.g. one that last succeeded three weeks ago.",
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        comment="Cleared on success, so the page shows only the current "
        "problem, not a history of past ones.",
    )

    sweep_lease_until: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment=(
            "Held while a sync runs against this target, so two can't run "
            "at once. A time-limited lease rather than a lock, because "
            "reconcile() commits between users (so a transaction lock can't "
            "span it) and a session lock isn't reliable through a "
            "transaction pooler. Expires on its own if a worker dies mid-sweep."
        ),
    )

    application: Mapped[Application] = relationship()
    links: Mapped[list[ProvisioningLink]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )

    @property
    def scim_root(self) -> str:
        """The base URL with no trailing slash, so paths join predictably."""
        return self.base_url.rstrip("/")

    def __repr__(self) -> str:
        return f"<ProvisioningTarget {self.base_url}>"


class ProvisioningLink(Base):
    """One of our people, as an account in one downstream.

    Kept after the account is deactivated rather than deleted, so history
    (who was deprovisioned, when, which account) stays answerable and a
    rehire revives the old account instead of creating a second one.
    """

    __tablename__ = "provisioning_links"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("provisioning_targets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )

    remote_id: Mapped[str | None] = mapped_column(
        String(255),
        comment="The id the downstream gave this account. Null if a create "
        "attempt failed, so a retry can tell 'never created' from "
        "'created, then broke'.",
    )

    state: Mapped[LinkState] = mapped_column(
        enum_type(LinkState),
        nullable=False,
        default=LinkState.PENDING,
        server_default=LinkState.PENDING.value,
    )

    last_pushed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    attempts: Mapped[int] = mapped_column(
        nullable=False,
        default=0,
        server_default=text("0"),
        comment="Consecutive failures, reset on success. Used to flag a "
        "link that keeps failing instead of retrying it silently forever.",
    )

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        nullable=False,
    )

    target: Mapped[ProvisioningTarget] = relationship(back_populates="links")
    user: Mapped[User] = relationship()

    @property
    def exists_downstream(self) -> bool:
        """Whether there is an account out there to update rather than create."""
        return self.remote_id is not None

    __table_args__ = (
        # One account per person per target, so a retry can't create a
        # duplicate if it doesn't notice the first attempt succeeded.
        UniqueConstraint("target_id", "user_id", name="one_account_per_person"),
        # The same remote account must not be claimed by two of our people.
        Index(
            "one_person_per_remote_account",
            "target_id",
            "remote_id",
            unique=True,
            postgresql_where=text("remote_id IS NOT NULL"),
        ),
        # The sync asks for everything that still needs doing.
        Index(
            "ix_provisioning_links_pending",
            "target_id",
            "state",
            postgresql_where=text("state <> 'active'"),
        ),
    )

    def __repr__(self) -> str:
        return f"<ProvisioningLink user={self.user_id} remote={self.remote_id} {self.state}>"
