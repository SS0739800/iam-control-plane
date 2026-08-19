"""The login inspector: what happened on every sign-in attempt, and why.

This is the payoff for doing the checks ourselves instead of calling one library
function. Every login writes all ten named results into its audit entry, so a
login that stopped working says "the clock is three minutes out" rather than
"invalid assertion". See docs/adr/0005-validate-assertions-ourselves.md.

There is no table behind this. It reads the audit log, which means the inspector
inherits the log's properties for free: entries can't be edited, can't be deleted,
and the tamper check covers them.
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement

from iam.api.pagination import MAX_LIMIT, CursorPage, clamp_limit, decode_cursor, encode_cursor
from iam.deps import SessionDep
from iam.models.audit import AuditEvent
from iam.models.enums import AuditOutcome
from iam.schemas.login_inspector import LoginAttempt, LoginAttemptDetail, LoginCheck
from iam.security import Permission, require

router = APIRouter(prefix="/saml/logins", tags=["login inspector"])

LOGIN_ACTIONS = ("saml.login_succeeded", "saml.login_failed")


def _checks(detail: dict[str, Any]) -> list[LoginCheck]:
    """The check results off an audit entry.

    Written defensively on purpose. These entries are permanent, so an entry from
    an older version of the code has whatever shape it had then, and the inspector
    has to keep working rather than 500 on the oldest row in the table.
    """
    raw = detail.get("checks")
    if not isinstance(raw, list):
        return []

    results = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        results.append(
            LoginCheck(
                name=str(item.get("name", "unknown")),
                passed=bool(item.get("passed", False)),
                detail=str(item.get("detail", "")),
            )
        )
    return results


def _attempt(event: AuditEvent) -> LoginAttempt:
    detail: dict[str, Any] = event.detail if isinstance(event.detail, dict) else {}
    checks = _checks(detail)

    return LoginAttempt(
        id=event.id,
        occurred_at=event.occurred_at,
        outcome=AuditOutcome(str(event.outcome)),
        idp=detail.get("idp") or event.target_label,
        who=event.actor_label,
        reason=detail.get("reason"),
        checks=checks,
        failed_checks=[check.name for check in checks if not check.passed],
        assertion_id=detail.get("assertion_id"),
        session_id=detail.get("session_id"),
        directory=detail.get("directory"),
        has_response=bool(detail.get("raw_response")),
    )


@router.get(
    "",
    response_model=CursorPage[LoginAttempt],
    summary="Every sign-in attempt, newest first",
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def list_login_attempts(
    session: SessionDep,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a previous page")] = None,
    outcome: Annotated[
        AuditOutcome | None, Query(description="Narrow to just the failures, usually")
    ] = None,
    idp: Annotated[str | None, Query(description="Only this provider, by short name")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
) -> CursorPage[LoginAttempt]:
    """Logins in the order they happened, most recent first.

    Cursors rather than page numbers, for the same reason the audit log uses them:
    new attempts arrive at the top, and page numbers would shift under you.
    """
    limit = clamp_limit(limit)
    filters: list[ColumnElement[bool]] = [AuditEvent.action.in_(LOGIN_ACTIONS)]

    if outcome is not None:
        filters.append(AuditEvent.outcome == outcome)
    if idp:
        # From the detail, not from target_label. A successful login names the
        # provider by its display name and a refused one by its slug, so filtering
        # on the target would match one and miss the other — and the failures are
        # the ones anybody comes to this screen for.
        filters.append(AuditEvent.detail["idp"].as_string() == idp)

    if cursor:
        try:
            after = decode_cursor(cursor)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        filters.append(AuditEvent.id < after)

    rows = (
        await session.scalars(
            select(AuditEvent).where(*filters).order_by(AuditEvent.id.desc()).limit(limit + 1)
        )
    ).all()

    has_more = len(rows) > limit
    page = list(rows[:limit])

    return CursorPage[LoginAttempt](
        items=[_attempt(event) for event in page],
        limit=limit,
        next_cursor=encode_cursor(page[-1].id) if has_more and page else None,
    )


@router.get(
    "/{event_id}",
    response_model=LoginAttemptDetail,
    summary="One attempt, with the assertion that arrived",
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def get_login_attempt(event_id: int, session: SessionDep) -> LoginAttemptDetail:
    """One login, including the document itself when we kept it.

    Only failures keep the document. A login that passed all ten checks has nothing
    to look at, and storing an assertion per login forever is a lot of somebody's
    personal data for no reason.

    The XML comes back as it arrived rather than reformatted. An inspector exists to
    show what was actually sent — reformatting is the one thing it shouldn't do.
    """
    event = await session.scalar(
        select(AuditEvent).where(AuditEvent.id == event_id, AuditEvent.action.in_(LOGIN_ACTIONS))
    )
    if event is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"No sign-in attempt with entry id {event_id}."
        )

    detail: dict[str, Any] = event.detail if isinstance(event.detail, dict) else {}
    stored = detail.get("raw_response")

    decoded: str | None = None
    if isinstance(stored, str) and stored:
        try:
            # Not validate=True: a truncated copy is no longer valid base64, and
            # showing most of a document beats showing none of it.
            decoded = base64.b64decode(stored).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            decoded = "(the stored response could not be decoded)"

    return LoginAttemptDetail(
        **_attempt(event).model_dump(),
        decoded_response=decoded,
        response_truncated=bool(detail.get("raw_response_truncated")),
    )
