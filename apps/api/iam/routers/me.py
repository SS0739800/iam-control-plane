"""Who am I.

The first thing the console asks on every load: is anybody signed in, and what
are they allowed to do. Its own endpoint rather than a field on the dashboard,
since it gets called on pages that have nothing to do with the dashboard.
"""

from __future__ import annotations

from fastapi import APIRouter

from iam.schemas.common import SignedInUser
from iam.security import CurrentActor

router = APIRouter(tags=["session"])


@router.get(
    "/me",
    response_model=SignedInUser,
    summary="The person this request is coming from",
)
async def me(actor: CurrentActor) -> SignedInUser:
    """Report the current person.

    No permission check: everybody is allowed to know who they are. Being
    signed in is the only requirement, which resolving the actor already checks.
    """
    return SignedInUser(
        id=actor.user_id,
        user_name=actor.user_name,
        display_name=actor.display_name,
        role=actor.role,
        permissions=sorted(str(permission) for permission in actor.permissions),
        via_saml_session=actor.session_id is not None,
    )
