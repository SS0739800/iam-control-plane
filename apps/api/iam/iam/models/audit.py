"""The audit log.

Two things make this table different from the rest.

You can only add to it. The migration sets up a database rule that rejects UPDATE
and DELETE outright, so nothing can quietly edit history, not even our own code
by mistake.

Every row carries a fingerprint of the row before it, so if someone does get in
and change an old entry, the check in iam.audit.chain spots it and says which one.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from iam.models.base import Base
from iam.models.enums import ActorType, AuditOutcome, enum_type

GENESIS_HASH = "0" * 64
"""What the very first entry points at, since there's nothing before it."""

HASH_LENGTH = 64
"""A SHA-256 fingerprint written as hex is always 64 characters."""


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # A counting number, not a UUID. "The row before this one" has to mean
    # something exact, and random UUIDs have no order to them.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ------------------------------------------------------------------ actor
    actor_type: Mapped[ActorType] = mapped_column(
        enum_type(ActorType),
        nullable=False,
    )

    # Not a foreign key, on purpose. If it were, deleting a user would either be
    # blocked or would take their history with them. The log has to outlast the
    # people in it.
    actor_id: Mapped[uuid.UUID | None] = mapped_column()

    actor_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="The person's name, copied in when the entry is written, so the "
        "entry still makes sense after their account is gone.",
    )

    # ----------------------------------------------------------------- action
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Dotted verb, e.g. 'user.created', 'group.member_added', "
        "'saml.login'. Stable strings — dashboards group on them.",
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_type(AuditOutcome),
        nullable=False,
    )

    # ----------------------------------------------------------------- target
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(255))
    target_label: Mapped[str | None] = mapped_column(String(255))

    # ---------------------------------------------------------------- context
    ip_address: Mapped[str | None] = mapped_column(String(45))
    """Sized for a full IPv6 literal."""

    user_agent: Mapped[str | None] = mapped_column(String(500))

    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        comment="Ties every event produced by one request or one sync run "
        "together. P6 relies on this to show a whole provisioning cascade.",
    )

    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        comment="Event-specific payload. In P2 this holds the decoded SAML "
        "assertion and its per-check validation results.",
    )

    # ------------------------------------------------------------- hash chain
    prev_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    hash: Mapped[str] = mapped_column(
        String(HASH_LENGTH),
        nullable=False,
        unique=True,
        comment="SHA-256 over this event's canonical form plus prev_hash.",
    )

    __table_args__ = (
        # The log is always shown newest first and paged by id, which the primary
        # key index already handles. These are for the filter dropdowns.
        Index("ix_audit_events_occurred_at", occurred_at.desc()),
        Index("ix_audit_events_action", "action"),
        Index("ix_audit_events_actor_id", "actor_id"),
        Index("ix_audit_events_outcome", "outcome"),
        Index("ix_audit_events_target", "target_type", "target_id"),
        Index("ix_audit_events_correlation_id", "correlation_id"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent #{self.id} {self.action} {self.outcome}>"
