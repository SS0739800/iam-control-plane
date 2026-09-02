"""The systems we push accounts into, and what we pushed where.

Who gets provisioned is not a new question
------------------------------------------

A target belongs to an application, and the people pushed to it are the people who
have access to that application. That is the whole rule, and it is deliberate: this
phase adds no second notion of who should be where.

``app_assignments`` already answers "who should have this", directly or through a
group. P5 reads it to decide whether to sign a login. P6 reads the same rows to
decide whose account to create. So granting somebody access provisions them, and
removing it deprovisions them, without anybody maintaining a separate list that
could disagree with the first one.

Why the links table exists
--------------------------

A downstream gives an account its own id, and we have to keep it. Without it the
only way to update or deactivate somebody is to search by username on every push and
hope the answer is unique — which fails exactly when it matters, because somebody
whose username changed is the person most likely to be mid-leaver-process.

So each link is one row saying "our person X is their account Y", plus what happened
last time we tried. That last part is what makes a failure visible instead of a push
that quietly stopped happening.
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
        comment="Which application this provisions. Unique: one target per "
        "application, because two would race each other writing the same accounts.",
    )

    base_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="The downstream's SCIM root, e.g. https://example/scim/v2. Checked "
        "against ADR 0007 when it is set, not on every push.",
    )

    token_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="The bearer token, encrypted. See iam/secrets.py for why this one is "
        "encrypted rather than hashed like the inbound tokens.",
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="Turning a target off stops pushes without losing the links, so "
        "turning it back on does not recreate every account.",
    )

    address_concession: Mapped[str | None] = mapped_column(
        String(255),
        comment="A rule from ADR 0007 that was relaxed to allow this address — a "
        "private address, or plain HTTP. Stored so the page can show it was a "
        "decision rather than an oversight.",
    )

    # ------------------------------------------------------ how it last went
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_ok: Mapped[bool | None] = mapped_column(
        Boolean,
        comment="Null means never tried. The useful question is the negative one: a "
        "target that last succeeded three weeks ago is one nobody is watching.",
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        comment="Kept after a failure and cleared on success, so the page shows the "
        "current problem rather than a history of them.",
    )

    sweep_lease_until: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment=(
            "Held while a sync is running against this target, so two of them cannot "
            "run at once. A lease rather than a lock because reconcile() commits "
            "between every person and a transaction-scoped lock cannot span that, "
            "while a session-scoped one is unreliable through a transaction pooler "
            "that may hand out a different backend per transaction. Expires on its "
            "own, so a worker dying mid-sweep does not wedge the target."
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

    Kept after the account is deactivated rather than deleted. "We deprovisioned her
    from Salesforce on the 3rd, and here is the id we deactivated" is the question
    this table exists to answer, and deleting the row makes it unanswerable — while
    also meaning a rehire creates a second account instead of reviving the first.
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
        comment="The id the downstream gave this account. Null while a link exists "
        "but no account does yet — which is the state a failed create leaves behind, "
        "and is why a retry can tell 'never created' from 'created and then broke'.",
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
        comment="Consecutive failures. Reset on success. A link failing forever is "
        "worth telling somebody about rather than retrying quietly.",
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
        # One account per person per target. Without it a retry that did not notice
        # the first attempt succeeded creates a duplicate, and duplicates in a
        # downstream directory are the hardest kind of mess to unpick — both accounts
        # look legitimate.
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
