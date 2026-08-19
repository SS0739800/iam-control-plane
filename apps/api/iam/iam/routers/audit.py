"""Reading the audit log and running the tamper check.

The list uses cursors instead of page numbers. See iam.api.pagination for the
detail. Short version: skipping 45,000 rows is slow, and new entries arriving at
the top would make page numbers shift under you while scrolling.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from iam.api.pagination import MAX_LIMIT, CursorPage, clamp_limit, decode_cursor, encode_cursor
from iam.audit import verify_chain
from iam.deps import SessionDep
from iam.models.audit import AuditEvent
from iam.models.enums import AuditOutcome
from iam.schemas.audit import AuditEventOut, ChainVerification
from iam.security import Permission, require

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "",
    response_model=CursorPage[AuditEventOut],
    summary="Read the audit log, newest first",
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def list_events(
    session: SessionDep,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a previous page")] = None,
    action: Annotated[str | None, Query(description="Exact action, e.g. user.updated")] = None,
    outcome: Annotated[AuditOutcome | None, Query()] = None,
    actor_id: Annotated[uuid.UUID | None, Query()] = None,
    target_type: Annotated[str | None, Query()] = None,
    correlation_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 50,
) -> CursorPage[AuditEventOut]:
    limit = clamp_limit(limit)
    filters = []

    if action:
        filters.append(AuditEvent.action == action)
    if outcome is not None:
        filters.append(AuditEvent.outcome == outcome)
    if actor_id is not None:
        filters.append(AuditEvent.actor_id == actor_id)
    if target_type:
        filters.append(AuditEvent.target_type == target_type)
    if correlation_id is not None:
        filters.append(AuditEvent.correlation_id == correlation_id)

    if cursor:
        try:
            after = decode_cursor(cursor)
        except ValueError as exc:
            # Bad cursor means the caller sent something wrong, so 400 not 500.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        filters.append(AuditEvent.id < after)

    # Ask for one extra row. If we get it, there's another page. Cheaper than
    # counting a table that only ever grows.
    rows = (
        await session.scalars(
            select(AuditEvent).where(*filters).order_by(AuditEvent.id.desc()).limit(limit + 1)
        )
    ).all()

    has_more = len(rows) > limit
    page = list(rows[:limit])

    return CursorPage[AuditEventOut](
        items=[AuditEventOut.model_validate(row) for row in page],
        limit=limit,
        next_cursor=encode_cursor(page[-1].id) if has_more and page else None,
    )


@router.get(
    "/verify",
    response_model=ChainVerification,
    summary="Verify the hash chain",
    dependencies=[Depends(require(Permission.AUDIT_VERIFY))],
)
async def verify(
    session: SessionDep,
    limit: Annotated[
        int | None,
        Query(ge=1, description="Stop after this many events. Omit to verify everything."),
    ] = None,
) -> ChainVerification:
    """Check the log and report the first entry that doesn't add up.

    A broken log still comes back as 200 with `valid: false`. The check itself
    worked, and what it found is the answer. A 500 would mean the check couldn't
    run, which is a different problem.
    """
    result = await verify_chain(session, limit=limit)
    return ChainVerification(
        valid=result.valid,
        events_checked=result.events_checked,
        broken_at_id=result.broken_at_id,
        reason=result.reason,
    )
