"""The access review: what somebody should actually look at.

Guarded by audit:read, which auditor, helpdesk and admin all hold. This is review
work rather than a change, and the person whose job is reviewing access should not
need the permission to grant it — the whole point of the auditor role is that those
two are separate.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends

from iam.access.review import run
from iam.deps import SessionDep
from iam.schemas.review import AccessReviewOut, FindingOut
from iam.security import Permission, require

router = APIRouter(prefix="/access-review", tags=["access review"])


@router.get(
    "",
    response_model=AccessReviewOut,
    summary="Things worth asking about",
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def access_review(session: SessionDep) -> AccessReviewOut:
    """Run every check and report what turned up, worst first.

    Computed on request rather than stored. The answer changes whenever anybody
    grants anything, and a cached review is one that tells an auditor about a
    problem somebody fixed last week.
    """
    result = await run(session, now=dt.datetime.now(dt.UTC))

    return AccessReviewOut(
        checked_at=result.checked_at,
        clean=result.clean,
        counts=result.by_severity,
        findings=[
            FindingOut(
                kind=finding.kind,
                severity=finding.severity,
                subject=finding.subject,
                subject_user_id=finding.subject_user_id,
                concern=finding.concern,
                suggested_action=finding.suggested_action,
                since=finding.since,
            )
            for finding in result.findings
        ],
    )
