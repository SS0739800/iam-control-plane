"""Issue a bearer token for a system that pushes accounts to us over SCIM.

    python -m scripts.issue_scim_token "authentik (local)"

Prints the token once. Only its hash is stored, so this is the only moment it
exists in readable form — if it is lost, issue another and revoke this one.
There is deliberately no way to read it back out.

The token is what lets something write to the directory: create people, rename
them, switch them off. Treat it like a password, because that is what it is.

Revoking one, when you need to:

    UPDATE scim_clients
       SET revoked_at = now(), revoked_reason = 'rotated'
     WHERE name = 'authentik (local)';

The row stays either way, so "that sync stopped on the 3rd because we revoked it"
is still answerable afterwards.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from iam.config import get_settings
from iam.db import build_engine, build_sessionmaker
from iam.models.scim import ScimClient
from iam.security.tokens import hash_token, new_token


async def issue(name: str, description: str | None) -> str:
    settings = get_settings()
    engine = build_engine(settings)
    token = new_token()

    try:
        async with build_sessionmaker(engine)() as session:
            existing = await session.scalar(select(ScimClient).where(ScimClient.name == name))
            if existing is not None:
                raise SystemExit(
                    f"A SCIM client called {name!r} already exists. Revoke it first, or "
                    f"choose another name — two clients sharing a name makes the audit "
                    f"log ambiguous about which one acted."
                )

            session.add(
                ScimClient(
                    name=name,
                    token_hash=hash_token(token),
                    description=description,
                    enabled=True,
                )
            )
            await session.commit()
    finally:
        await engine.dispose()

    return token


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    name = sys.argv[1]
    description = sys.argv[2] if len(sys.argv) > 2 else None

    token = asyncio.run(issue(name, description))

    print(f"\nSCIM client {name!r} created.\n")
    print("Token (shown once, store it now):\n")
    print(f"  {token}\n")
    print("Give it to the provider as: Authorization: Bearer <token>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
