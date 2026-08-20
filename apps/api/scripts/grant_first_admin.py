"""Make the first person an admin, on a database that has none.

    python -m scripts.grant_first_admin someone@example.com

Why this exists
---------------

There is no root account, on purpose. Somebody created by logging in starts as an
employee with no console permissions, so there is no path from "the identity
provider let them in" to "they can change things here". That is the right default
and it leaves exactly one gap: a brand new deployment has nobody who can grant
anything, including the first admin.

This closes that gap and nothing else.

Why not just UPDATE the column
------------------------------

Because ``users.platform_role`` is a *cache*. The truth is in ``role_grants``, and
``iam/access/roles.py`` is the only thing meant to write the column. A raw UPDATE
produces a person the console shows as an admin with no grant behind them — exactly
the inconsistency ``find_drift`` exists to report, planted deliberately on the first
day of the deployment's life.

So this goes through ``grant_role``, the same function the console calls, and writes
the same audit entry. The result is indistinguishable from an admin granted by a
person, apart from the label saying it came from this script.

Why it refuses to run twice
---------------------------

A bootstrap that works whenever you feel like it is a backdoor. Once an admin
exists, granting another is a decision somebody with the authority should make in
the console, where it is subject to the same rules and shows up on the audit log as
an ordinary act. So this refuses if any live admin grant is already there.

The refusal is the feature. If it fires unexpectedly, somebody already has admin on
this database and the interesting question is who.
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

    Checks the grants rather than ``users.platform_role``, because the grants are
    the truth and the column is a cache of them. A database where the two disagree
    should still refuse — and the drift is worth knowing about separately.

    Expiry is checked here rather than left to ``expire_due_grants``. An admin grant
    that has run out but has not been swept yet still has ``revoked_at`` unset, and
    treating that as somebody holding admin would block the bootstrap on a
    deployment where in fact nobody can log in and grant anything. That is exactly
    the situation this script exists for.
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
                # Almost always because they have not logged in yet. Said plainly,
                # because "no such user" invites a hunt for a typo when the answer
                # is usually "sign in first".
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
                # No user_id: nobody granted this, a script did, and pretending
                # otherwise would put a person's name on a decision they did not
                # make.
                granter=Granter(user_id=None, label=GRANTER_LABEL),
                now=now,
                reason=reason,
            )

            await append_event(
                session,
                AuditDraft(
                    action="role.granted",
                    # SYSTEM rather than USER for the same reason the granter has no
                    # id. This is the one admin grant on the whole log that nobody
                    # is accountable for, and it should be obvious which one it is.
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
                        # The whole point of the entry: this is the grant that had
                        # no grantor, and the audit log should say so rather than
                        # leaving somebody to work it out.
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
