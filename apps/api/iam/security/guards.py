"""Permission guards for route handlers.

Usage::

    @router.get("/users", dependencies=[Depends(require(Permission.USERS_READ))])
    async def list_users(...) -> Page[UserSummary]: ...

or, when the handler needs the actor itself::

    async def deactivate(actor: Annotated[Actor, Depends(require(Permission.USERS_WRITE))]):
        ...
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, status

from iam.security.actor import Actor, CurrentActor
from iam.security.permissions import Permission

logger = logging.getLogger(__name__)


def require(*permissions: Permission) -> Callable[[Actor], Awaitable[Actor]]:
    """Make a check that requires every permission listed.

    All of them, not any one of them. Adding someone to a group touches users
    and groups, so it asks for both; accepting just one would let people do
    more than they should.
    """
    if not permissions:
        raise ValueError("require() needs at least one permission")

    required = frozenset(permissions)

    async def dependency(actor: CurrentActor) -> Actor:
        missing = required - actor.permissions
        if missing:
            # Logged, not written to the audit log. Writing takes a lock, so
            # recording every rejected request would let anyone slow the log
            # down by spamming requests they aren't allowed to make. P4 adds
            # these as real audit entries once there's rate limiting in front.
            logger.warning(
                "authz.denied",
                extra={
                    "actor": actor.user_name,
                    "role": str(actor.role),
                    "missing": sorted(str(p) for p in missing),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Missing required permission: " + ", ".join(sorted(str(p) for p in missing))
                ),
            )
        return actor

    return dependency
