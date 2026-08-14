"""Shapes for the login inspector.

These are a view over the audit log rather than a table of their own. Every login
already writes its ten check results into its audit entry, so the inspector is a
read: nothing here records anything, and nothing here can be edited, because the
log it reads from refuses both.
"""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field

from iam.models.enums import AuditOutcome


class LoginCheck(BaseModel):
    """One of the ten checks, and how it went."""

    name: str
    passed: bool
    detail: str = Field(
        description="Why it passed or failed, in words. The useful part when it failed."
    )


class LoginAttempt(BaseModel):
    """One login, accepted or refused.

    A single pass/fail tells you nothing when a login mysteriously stops working
    against a new provider. Ten named results tell you it was the clock.
    """

    id: int = Field(description="The audit entry this came from.")
    occurred_at: dt.datetime
    outcome: AuditOutcome
    idp: str | None = Field(default=None, description="Which provider, by short name.")
    who: str = Field(description="The person on a successful login, the provider on a failed one.")

    reason: str | None = Field(default=None, description="Why it was refused.")
    # No defaults on these three: the endpoint always sends them, and a default
    # would make them optional in the published schema, which pushes an
    # "is it missing?" branch into every client for a case that never happens.
    checks: list[LoginCheck]
    failed_checks: list[str] = Field(description="Names of the checks that did not pass.")

    assertion_id: str | None = None
    session_id: str | None = Field(
        default=None, description="The session this login became, if it was accepted."
    )
    directory: str | None = Field(
        default=None,
        description=(
            "What the login did to the directory: created somebody, refreshed "
            "their details, or nothing."
        ),
    )

    has_response: bool = Field(
        description=(
            "Whether the assertion itself was kept. Only failures keep it — a login "
            "that passed every check has nothing to look at."
        ),
    )


class LoginAttemptDetail(LoginAttempt):
    """One login, with the document that arrived."""

    decoded_response: str | None = Field(
        description=(
            "The assertion as it arrived, decoded but not reformatted. An inspector "
            "should show what was actually sent, not a tidied-up version of it."
        ),
    )
    response_truncated: bool = Field(description="Whether the stored copy was cut short.")
