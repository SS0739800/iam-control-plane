"""Somebody asking for access, and somebody answering.

Covers access that doesn't follow from an access rule, e.g. a one-off need
with no matching attribute. Requests are kept forever in whatever state
they ended in (including withdrawn and denied) as an audit trail, not a
queue that gets cleaned out. States after PENDING are final; asking again
means filing a new request.

The decision columns are separate from the requester columns so the
database can enforce that they differ (no self-approval). Also checked in
the service layer, see iam/access/requests.py.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from iam.models.base import Base
from iam.models.enums import RequestState, enum_type
from iam.models.mixins import Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from iam.models.group import Group
    from iam.models.user import User


class AccessRequest(UUIDPrimaryKey, Timestamps, Base):
    """One person asking to be put in one group."""

    __tablename__ = "access_requests"

    # ---------------------------------------------------------- who is asking
    requester_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    requester_label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Copy of their name at the time, so the request still reads "
        "correctly if their record changes or is deleted.",
    )

    # ------------------------------------------------------- what they want
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    group_label: Mapped[str] = mapped_column(String(255), nullable=False)

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Why they need it. Required, so the approver has something "
        "to actually decide on.",
    )

    # ------------------------------------------------------------- the answer
    state: Mapped[RequestState] = mapped_column(
        enum_type(RequestState),
        nullable=False,
        default=RequestState.PENDING,
        server_default=RequestState.PENDING.value,
    )

    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    decided_by_label: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(
        Text,
        comment="What the approver said.",
    )

    expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        comment="If approved, when the access should end. Carried onto the "
        "membership so temporary access is temporary.",
    )

    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    group: Mapped[Group] = relationship()

    @property
    def is_open(self) -> bool:
        return self.state == RequestState.PENDING

    @property
    def summary(self) -> str:
        """The request as a line of text, for an email or a log entry."""
        return f"{self.requester_label} asked for {self.group_label}"

    __table_args__ = (
        # Nobody can approve or deny their own request. Scoped to approved/
        # denied only, since a withdrawal is also the requester closing their
        # own request and that's fine.
        CheckConstraint(
            "state NOT IN ('approved', 'denied') "
            "OR decided_by_id IS NULL "
            "OR decided_by_id <> requester_id",
            name="approver_is_not_the_requester",
        ),
        # An approval or denial must record who and when. Cancellation is
        # exempt since nobody decided it, events overtook it.
        CheckConstraint(
            "state NOT IN ('approved', 'denied') "
            "OR (decided_by_label IS NOT NULL AND decided_at IS NOT NULL)",
            name="a_decision_has_an_author",
        ),
        # Only one open request per person per group, so double-clicking
        # can't create two.
        Index(
            "one_open_request_per_person_and_group",
            "requester_id",
            "group_id",
            unique=True,
            postgresql_where=text("state = 'pending'"),
        ),
        # The approver's queue, and the person's own list.
        Index("ix_access_requests_state", "state", postgresql_where=text("state = 'pending'")),
        Index("ix_access_requests_requester", "requester_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AccessRequest {self.requester_label} -> {self.group_label} [{self.state}]>"
