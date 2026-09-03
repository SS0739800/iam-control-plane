"""Bootstrapping the first admin.

The only test file here covering a script, since this is the one piece of
code that can create an admin without an admin asking for it.

There's no root account — someone created by logging in starts as an
employee with no permissions, so there's no path from "the provider let
them in" to "they can change things here." That leaves a gap on day one of
a deployment, when nobody exists who can grant anything. This script
closes it, so the refusal half matters most: a bootstrap that keeps
working after that is a backdoor.

Also checked: the grant is a *real* grant, not just `UPDATE users SET
platform_role = 'admin'`, which would look right everywhere while leaving
no grant behind it — exactly the drift find_drift exists to catch.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import delete, select

from iam.access import find_drift
from iam.audit.chain import verify_chain
from iam.models.access import RoleGrant
from iam.models.audit import AuditEvent
from iam.models.enums import ActorType, GrantSource, IdentitySource, PlatformRole
from iam.models.user import User
from scripts.grant_first_admin import GRANTER_LABEL, Refused, existing_admin
from scripts.grant_first_admin import bootstrap as bootstrap_admin
from tests.support import database_url, with_db

pytestmark = pytest.mark.integration


@pytest.fixture
async def people(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Two employees on a database with no admin.

    The script reads settings through get_settings(), so the database URL
    goes into the environment, matching how it runs for real.

    Patching iam.config.get_settings wouldn't work here: the script does
    `from iam.config import get_settings`, so it holds its own reference
    and never looks the module attribute up again. Setting the environment
    and clearing the lru_cache is what actually reaches it — cleared
    before the script runs, and again after so the next test doesn't
    inherit this URL.
    """
    url = database_url()
    monkeypatch.setenv("DATABASE_URL", url)

    from iam.config import get_settings

    get_settings.cache_clear()

    suffix = uuid.uuid4().hex[:12]
    first = f"first.{suffix}@demo.local"
    second = f"second.{suffix}@demo.local"

    async def make(session: Any) -> None:
        for name in (first, second):
            session.add(
                User(
                    user_name=name,
                    email=name,
                    display_name=name.split("@")[0],
                    active=True,
                    platform_role=PlatformRole.EMPLOYEE,
                    source=IdentitySource.JIT,
                )
            )
        await session.commit()

    await with_db(make)

    yield {"first": first, "second": second, "suffix": suffix}

    async def clean(session: Any) -> None:
        ids = (
            await session.scalars(select(User.id).where(User.user_name.like(f"%{suffix}%")))
        ).all()
        if ids:
            await session.execute(delete(RoleGrant).where(RoleGrant.user_id.in_(ids)))
            await session.execute(delete(User).where(User.id.in_(ids)))
        await session.commit()

    await with_db(clean)
    get_settings.cache_clear()


# --------------------------------------------------------------- it works once


async def test_it_makes_them_an_admin(people: dict[str, str]) -> None:
    assert await bootstrap_admin(people["first"], reason="first admin") == 0

    async def check(session: Any) -> None:
        person = await session.scalar(select(User).where(User.user_name == people["first"]))
        assert person is not None
        assert person.platform_role is PlatformRole.ADMIN

    await with_db(check)


async def test_the_grant_is_real_and_not_just_the_cached_column(people: dict[str, str]) -> None:
    """Rules out the tempting shortcut: an UPDATE on users.platform_role
    would pass the test above but leave no grant behind it, which
    find_drift would catch.
    """
    await bootstrap_admin(people["first"], reason="first admin")

    async def check(session: Any) -> None:
        person = await session.scalar(select(User).where(User.user_name == people["first"]))
        assert person is not None

        grant = await session.scalar(
            select(RoleGrant).where(
                RoleGrant.user_id == person.id,
                RoleGrant.revoked_at.is_(None),
            )
        )
        assert grant is not None, "the column was set with no grant behind it"
        assert grant.role is PlatformRole.ADMIN
        assert grant.granted_by_label == GRANTER_LABEL
        # Nobody granted it, so nothing claims to have.
        assert grant.granted_by_id is None

        drifted = await find_drift(session, now=dt.datetime.now(dt.UTC))
        mine = [d for d in drifted if d.user_id == person.id]
        assert mine == [], f"the cache and the grants disagree: {mine}"

    await with_db(check)


async def test_it_says_so_on_the_audit_log(people: dict[str, str]) -> None:
    """The one admin grant nobody is accountable for, and the log should say which."""
    await bootstrap_admin(people["first"], reason="because somebody has to be")

    async def check(session: Any) -> None:
        entry = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.target_label == people["first"])
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert entry is not None
        assert entry.action == "role.granted"
        # SYSTEM, not USER. Putting a person's name on this would be claiming they
        # made a decision they did not make.
        assert entry.actor_type is ActorType.SYSTEM
        assert entry.actor_id is None
        assert entry.actor_label == GRANTER_LABEL
        assert entry.detail["bootstrap"] is True
        assert entry.detail["reason"] == "because somebody has to be"

    await with_db(check)


async def test_the_audit_chain_still_verifies(people: dict[str, str]) -> None:
    """A script writing to the chain by hand is exactly how a chain gets broken."""
    await bootstrap_admin(people["first"], reason="first admin")

    async def check(session: Any) -> None:
        result = await verify_chain(session)
        assert result.valid, result.reason

    await with_db(check)


# ------------------------------------------------------------- and then refuses


async def test_it_refuses_once_an_admin_exists(people: dict[str, str]) -> None:
    """The half that stops this being a backdoor."""
    await bootstrap_admin(people["first"], reason="first admin")

    with pytest.raises(Refused, match="already an admin"):
        await bootstrap_admin(people["second"], reason="sneaking in")


async def test_the_refusal_names_who_already_has_it(people: dict[str, str]) -> None:
    """If this fires unexpectedly, the interesting question is who — so the message
    answers it rather than making somebody go and look."""
    await bootstrap_admin(people["first"], reason="first admin")

    with pytest.raises(Refused) as refused:
        await bootstrap_admin(people["second"], reason="sneaking in")

    assert people["first"] in str(refused.value)


async def test_the_second_person_gains_nothing_from_the_attempt(people: dict[str, str]) -> None:
    await bootstrap_admin(people["first"], reason="first admin")

    with pytest.raises(Refused):
        await bootstrap_admin(people["second"], reason="sneaking in")

    async def check(session: Any) -> None:
        person = await session.scalar(select(User).where(User.user_name == people["second"]))
        assert person is not None
        assert person.platform_role is PlatformRole.EMPLOYEE

        grant = await session.scalar(select(RoleGrant).where(RoleGrant.user_id == person.id))
        assert grant is None

    await with_db(check)


async def test_it_refuses_somebody_who_does_not_exist(people: dict[str, str]) -> None:
    """Almost always because they have not logged in yet, so the message says that
    rather than inviting a hunt for a typo."""
    with pytest.raises(Refused, match="log in"):
        await bootstrap_admin(f"ghost.{people['suffix']}@demo.local", reason="nope")


async def test_existing_admin_reads_the_grants_not_the_column(people: dict[str, str]) -> None:
    """Plants the drift this script must not be fooled by: someone who set
    the column by hand looks like an admin on every screen, but the check
    looks at the grants, since that's where the truth is.
    """

    async def plant(session: Any) -> None:
        person = await session.scalar(select(User).where(User.user_name == people["first"]))
        assert person is not None
        person.platform_role = PlatformRole.ADMIN
        await session.commit()

    await with_db(plant)

    async def check(session: Any) -> None:
        # No grant exists, so this correctly reports none — the column is a cache and
        # lying to it proves nothing.
        assert await existing_admin(session, now=dt.datetime.now(dt.UTC)) is None

    await with_db(check)


async def test_an_expired_admin_grant_does_not_block_the_bootstrap(
    people: dict[str, str],
) -> None:
    """An admin grant that's run out still has revoked_at unset until
    expire_due_grants sweeps it. Counting that as someone holding admin
    would refuse the bootstrap exactly when nobody can log in to grant
    anything — the situation this script exists for.
    """

    async def plant_expired(session: Any) -> None:
        person = await session.scalar(select(User).where(User.user_name == people["second"]))
        assert person is not None
        session.add(
            RoleGrant(
                user_id=person.id,
                role=PlatformRole.ADMIN,
                source=GrantSource.DIRECT,
                granted_by_label="somebody who has since left",
                # Ran out yesterday, and nothing has swept it.
                expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(days=1),
                revoked_at=None,
            )
        )
        await session.commit()

    await with_db(plant_expired)

    async def confirm_not_counted(session: Any) -> None:
        assert await existing_admin(session, now=dt.datetime.now(dt.UTC)) is None

    await with_db(confirm_not_counted)

    # And the bootstrap goes ahead.
    assert await bootstrap_admin(people["first"], reason="nobody else can") == 0
