"""The audit log.

Append-only: a database rule rejects UPDATE and DELETE on this table.
Each row also hashes the previous row, so iam.audit.chain can detect and
locate tampering if a row is ever changed outside the app.
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

    # Sequential integer, not a UUID, so "the previous row" has a clear order.
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

    # Not a foreign key: audit rows must survive the user being deleted.
    actor_id: Mapped[uuid.UUID | None] = mapped_column()

    actor_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="The actor's name, copied in at write time so it survives "
        "account deletion.",
    )

    # ----------------------------------------------------------------- action
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Dotted verb, e.g. 'user.created', 'group.member_added', "
        "'saml.login'. Keep these stable, dashboards group on them.",
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
        comment="Ties together every event from one request or one sync run.",
    )

    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        comment="Event-specific payload, e.g. a decoded SAML assertion and "
        "its validation results.",
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
        # Paging by id uses the primary key index. These support filtering.
        Index("ix_audit_events_occurred_at", occurred_at.desc()),
        Index("ix_audit_events_action", "action"),
        Index("ix_audit_events_actor_id", "actor_id"),
        Index("ix_audit_events_outcome", "outcome"),
        Index("ix_audit_events_target", "target_type", "target_id"),
        Index("ix_audit_events_correlation_id", "correlation_id"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent #{self.id} {self.action} {self.outcome}>"
