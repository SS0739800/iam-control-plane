"""Checking that a SCIM request is from somebody we let write to the directory.

Bearer tokens, not the session cookie. The two are for different callers and
conflating them would be a mistake in both directions: a SCIM client is a machine
with no browser and no login, and a person's session should never be usable to
rewrite the directory wholesale.

That separation is also why this doesn't go through resolve_actor. An Actor is a
person with a role and a permission set; a SCIM client is not a person and has
exactly one power, which is to write the directory. Modelling it as an Actor
would mean inventing a fake user to hang it off, and then something in the
console would eventually treat that fake user as real.

Failures answer in SCIM's error shape, because a provider reading a FastAPI
``{"detail": ...}`` learns nothing it can act on.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Annotated

from fastapi import Depends, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from iam.db import get_session
from iam.models.scim import ScimClient
from iam.scim.errors import ScimError
from iam.security.tokens import hash_token

logger = logging.getLogger(__name__)

BEARER_PREFIX = "bearer "

LAST_USED_INTERVAL = dt.timedelta(minutes=5)
"""How stale the last-used stamp has to be before we write a new one.

A full sync is thousands of requests in a couple of minutes. Stamping every one
would turn a read into a write for no benefit — the question this column answers
is "has this token been used this month", and five minutes of lag is invisible
to it.
"""


def _unauthorised(detail: str) -> ScimError:
    """401 in SCIM's shape.

    No scimType: the spec doesn't define one for authentication, and inventing a
    value is worse than leaving it out.
    """
    return ScimError(status.HTTP_401_UNAUTHORIZED, detail)


def bearer_token(request: Request) -> str:
    """Pull the token out of the Authorization header.

    Raises:
        ScimError: 401 if the header is missing or isn't a bearer token.
    """
    header = request.headers.get("authorization", "")

    # Case-insensitive on the scheme, because RFC 7235 says the scheme is
    # case-insensitive and providers do send "Bearer" and "bearer".
    if not header.lower().startswith(BEARER_PREFIX):
        raise _unauthorised("This endpoint needs a bearer token: Authorization: Bearer <token>.")

    token = header[len(BEARER_PREFIX) :].strip()
    if not token:
        raise _unauthorised("The Authorization header carried no token.")

    return token


async def authenticate_scim_client(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScimClient:
    """Work out which SCIM client is calling, or refuse the request.

    The token is looked up by its hash, so a database that leaks doesn't hand
    anybody the ability to write to the directory.

    Every failure says the same thing. "No such token" and "that token was
    revoked" are different facts, and telling them apart out loud would let
    somebody with a list of candidate tokens learn which ones were once real.

    Raises:
        ScimError: 401 for a missing, unknown, revoked or disabled token.
    """
    token = bearer_token(request)

    client = await session.scalar(
        select(ScimClient).where(ScimClient.token_hash == hash_token(token))
    )

    if client is None or not client.is_usable:
        logger.warning(
            "scim.auth_failed",
            extra={
                "known_token": client is not None,
                "client": client.name if client else None,
                "ip": request.client.host if request.client else None,
            },
        )
        raise _unauthorised("That bearer token is not valid.")

    now = dt.datetime.now(dt.UTC)
    if client.last_used_at is None or now - client.last_used_at >= LAST_USED_INTERVAL:
        await session.execute(
            update(ScimClient).where(ScimClient.id == client.id).values(last_used_at=now)
        )
        await session.commit()

    return client


ScimClientDep = Annotated[ScimClient, Depends(authenticate_scim_client)]
"""Inject the calling SCIM client, having checked its token."""
