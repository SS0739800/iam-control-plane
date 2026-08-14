"""Who am I.

The first thing the console asks on every load: is anybody signed in, and what
are they allowed to do. Deliberately its own tiny surface rather than a field
bolted onto the dashboard, because it answers a different question and gets
called on pages the dashboard has nothing to do with.
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

    No permission check on this one on purpose: everybody is allowed to know who
    they are. Being signed in at all is the only requirement, and that's what
    resolving the actor already established.
    """
    return SignedInUser(
        id=actor.user_id,
        user_name=actor.user_name,
        display_name=actor.display_name,
        role=actor.role,
        permissions=sorted(str(permission) for permission in actor.permissions),
        via_saml_session=actor.session_id is not None,
    )
