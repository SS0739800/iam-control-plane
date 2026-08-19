"""Somebody asking for access, and somebody answering.

The other half of entitlements. Rules cover access that follows from who you are;
this covers the rest — the person who needs the finance system for one quarter and
has no attribute that says so.

Requests are records, not tasks
------------------------------

A request is kept forever in whatever state it ended in, including withdrawn and
denied. That is deliberate and it is the difference between a queue and an audit
trail: "we asked for this twice and were refused both times" is a fact somebody
will eventually need, and a system that deletes closed requests cannot produce it.

Nothing here reopens. Every state after pending is final, because a request that
could go back to pending would make "who approved this" have more than one answer.
Asking again means a new request, which is honest about there having been two.

One person cannot do both halves
--------------------------------

The decision columns exist separately from the requester columns so the database
can hold the rule that they differ. Self-approval is the failure that makes an
approval step decoration, and it is checked in the service layer as well — see
iam/access/requests.py.
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
        comment="Copy of their name at the time, so the request still reads properly "
        "if their record changes or goes.",
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
        comment="Why they need it. Required, because an approver with no reason in "
        "front of them is rubber-stamping rather than deciding.",
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
        comment="What the approver said. The most useful column here during a review, "
        "and the one most likely to be left empty.",
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
        # Somebody cannot approve or deny their own request. Held here as well as
        # in the service layer, because this is the one rule that makes the
        # approval step worth having, and a rule that lives only in application
        # code is one refactor away from not existing.
        #
        # Scoped to approved and denied on purpose. A withdrawal is also somebody
        # closing their own request, and there the requester *is* the correct
        # author — so the rule is about who may decide, not about who may write to
        # the row.
        CheckConstraint(
            "state NOT IN ('approved', 'denied') "
            "OR decided_by_id IS NULL "
            "OR decided_by_id <> requester_id",
            name="approver_is_not_the_requester",
        ),
        # An approval or refusal has to say who and when. Half a decision is worse
        # than none: it looks answered and cannot be attributed. Cancellation is
        # exempt because nobody decided it — events overtook it.
        CheckConstraint(
            "state NOT IN ('approved', 'denied') "
            "OR (decided_by_label IS NOT NULL AND decided_at IS NOT NULL)",
            name="a_decision_has_an_author",
        ),
        # Only one open request per person per group. Without it, clicking twice
        # makes two, and two approvals of the same thing look like two decisions.
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
