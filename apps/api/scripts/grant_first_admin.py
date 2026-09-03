"""Make the first person an admin, on a database that has none.

    python -m scripts.grant_first_admin someone@example.com

There's no root account: somebody created by logging in starts as an employee
with no console permissions. That leaves one gap — a brand new deployment has
nobody who can grant anything, including the first admin. This closes that gap
and nothing else.

Goes through ``grant_role``, the same function the console uses, rather than
updating ``users.platform_role`` directly — that column is just a cache of
``role_grants``, and a raw UPDATE would produce an admin with no grant behind
them (the exact inconsistency ``find_drift`` exists to catch).

Refuses to run if a live admin grant already exists, so it can't be used as a
standing backdoor — granting further admins after the first one is a console
decision, not a script's.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import sys

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access import Granter, RoleGrantRefused, grant_role
from iam.audit import AuditDraft, append_event
from iam.config import get_settings
from iam.db import build_engine, build_sessionmaker
from iam.models.access import RoleGrant
from iam.models.enums import ActorType, AuditOutcome, PlatformRole
from iam.models.user import User

GRANTER_LABEL = "scripts.grant_first_admin (bootstrap)"


class Refused(Exception):
    """This is not a database that needs bootstrapping."""


async def existing_admin(db: AsyncSession, *, now: dt.datetime) -> RoleGrant | None:
    """A live, unexpired admin grant, if there is one.

    Checks ``role_grants`` rather than ``users.platform_role``, which is only a
    cache and might disagree.

    Expiry is checked here rather than left to ``expire_due_grants``, since a
    grant that expired but hasn't been swept yet still has ``revoked_at`` unset.
    Treating that as someone holding admin would block the bootstrap exactly
    when nobody can actually log in and grant anything.
    """
    found: RoleGrant | None = await db.scalar(
        select(RoleGrant)
        .where(
            RoleGrant.role == PlatformRole.ADMIN,
            RoleGrant.revoked_at.is_(None),
            or_(RoleGrant.expires_at.is_(None), RoleGrant.expires_at > now),
        )
        .order_by(RoleGrant.created_at)
        .limit(1)
    )
    return found


async def bootstrap(user_name: str, *, reason: str) -> int:
    settings = get_settings()
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)
    now = dt.datetime.now(dt.UTC)

    try:
        async with sessionmaker() as session:
            already = await existing_admin(session, now=now)
            if already is not None:
                holder = await session.get(User, already.user_id)
                whom = holder.user_name if holder else already.user_id
                raise Refused(
                    f"There is already an admin on this database: {whom}, granted "
                    f"{already.created_at:%Y-%m-%d} by {already.granted_by_label}. "
                    "Grant further admins from the console, where the decision is "
                    "recorded as somebody's rather than a script's."
                )

            person = await session.scalar(select(User).where(User.user_name == user_name))
            if person is None:
                # Almost always because they haven't logged in yet, not a typo.
                raise Refused(
                    f"Nobody here is called {user_name!r}. A person is created the "
                    "first time they log in, so sign in through the identity "
                    "provider once and then run this again. The users table will "
                    "show who exists so far."
                )

            grant = await grant_role(
                session,
                person,
                role=PlatformRole.ADMIN,
                # No user_id: a script granted this, not a person.
                granter=Granter(user_id=None, label=GRANTER_LABEL),
                now=now,
                reason=reason,
            )

            await append_event(
                session,
                AuditDraft(
                    action="role.granted",
                    # SYSTEM rather than USER, same reason the granter has no id.
                    actor_type=ActorType.SYSTEM,
                    actor_id=None,
                    actor_label=GRANTER_LABEL,
                    outcome=AuditOutcome.SUCCESS,
                    target_type="user",
                    target_id=str(person.id),
                    target_label=person.user_name,
                    detail={
                        "role": str(PlatformRole.ADMIN),
                        "reason": reason,
                        "expires_at": None,
                        "granted_by": GRANTER_LABEL,
                        "self_grant": False,
                        "bootstrap": True,
                    },
                ),
            )
            await session.commit()

            print(f"{person.user_name} is now an admin.")
            print(f"  grant: {grant.id}")
            print("  Every later admin should be granted from the console.")
            return 0
    finally:
        await engine.dispose()


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "user_name",
        help="Who to make an admin. They must exist, so log in once first.",
    )
    parser.add_argument(
        "--reason",
        default="Bootstrapping the first admin on a new deployment.",
        help="Recorded on the grant and in the audit log.",
    )
    args = parser.parse_args()

    try:
        return await bootstrap(args.user_name, reason=args.reason)
    except (Refused, RoleGrantRefused) as refused:
        print(f"Refused: {refused}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
