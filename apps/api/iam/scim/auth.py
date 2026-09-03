"""Checking that a SCIM request is from somebody we let write to the directory.

Uses bearer tokens, not the session cookie. A SCIM client is a machine with
no browser and no login, and a person's session should never be usable to
rewrite the whole directory.

This also doesn't go through resolve_actor: an Actor is a person with a role
and a permission set, but a SCIM client isn't a person - it has exactly one
power, writing the directory. Modeling it as an Actor would mean inventing a
fake user for it, and something in the console would eventually treat that
fake user as real.

Failures answer in SCIM's error shape, since a provider reading a FastAPI
`{"detail": ...}` can't act on that.
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
from iam.tokens import hash_token

logger = logging.getLogger(__name__)

BEARER_PREFIX = "bearer "

LAST_USED_INTERVAL = dt.timedelta(minutes=5)
"""How stale the last-used stamp has to be before we write a new one.

A full sync is thousands of requests in a couple of minutes. Stamping every
one would turn a read into a write for no benefit - this column only needs
to answer "has this token been used this month", and five minutes of lag
doesn't matter for that.
"""


def _unauthorised(detail: str) -> ScimError:
    """401 in SCIM's shape.

    No scimType: the spec doesn't define one for authentication, and
    inventing a value is worse than leaving it out.
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

    The token is looked up by its hash, so a leaked database doesn't hand
    anybody the ability to write to the directory.

    Every failure says the same thing, even though "no such token" and "that
    token was revoked" are different facts - telling them apart would let
    someone with a list of candidate tokens learn which ones were once real.

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
