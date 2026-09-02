"""Refusing the two deactivations that cannot be undone.

Marking somebody as having left is the most consequential thing the console does:
it revokes every session they hold immediately, and ``/saml/acs`` refuses their next
login — a provider will happily sign them in, and ours is the answer that counts.

There is no self-service way back. ``active`` is set to true only when a user row is
*created*, so logging in again does not rescue anybody, and ``grant_first_admin``
grants a role rather than reactivating a person. Recovery means SSH and hand-written
SQL.

Two cases turn that from a strong action into an unrecoverable one, and neither was
guarded when the console first grew a button for this:

**Deactivating yourself.** Your sessions end mid-request and you cannot sign back in.

**Deactivating the last admin.** Nobody is left who can grant anything, including the
ability to undo it. The rule already existed for *revoking* an admin's grant, in
iam/routers/access.py — but switching somebody off empties the same set just as
surely, and that door was open.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access import count_live_admins, grant_role
from iam.access.roles import Granter
from iam.models.access import RoleGrant
from iam.models.enums import IdentitySource, PlatformRole
from iam.models.user import User
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration

BOOTSTRAP = Granter(user_id=None, label="tests")


@pytest.fixture
def somebody(console: ConsoleUsers) -> Iterator[uuid.UUID]:
    """An ordinary person, safe to deactivate.

    Cleaned up afterwards, and that matters more than it looks here. One test promotes
    this person to admin, and "is this the last admin" is a question about the whole
    database — so a leaked admin from a failed run makes the last-admin test pass for
    the wrong reason on the next one. That is exactly what happened while writing this
    file: two leftover admins sat in the test database and the guard correctly declined
    to fire.
    """
    user_name = f"leaver.{console.suffix}@demo.local"

    async def make(session: AsyncSession) -> uuid.UUID:
        person = User(
            user_name=user_name,
            email=user_name,
            display_name=f"Leaver {console.suffix}",
            active=True,
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.MANUAL,
        )
        session.add(person)
        await session.flush()
        await session.commit()
        return person.id

    user_id = run_db(make)
    yield user_id

    async def remove(session: AsyncSession) -> None:
        await session.execute(delete(RoleGrant).where(RoleGrant.user_id == user_id))
        await session.execute(delete(User).where(User.id == user_id))
        await session.commit()

    run_db(remove)


def active_of(user_id: uuid.UUID) -> bool:
    async def read(session: AsyncSession) -> bool:
        person = await session.get(User, user_id)
        assert person is not None
        return person.active

    return run_db(read)


# ------------------------------------------------- deactivating somebody else


def test_an_ordinary_person_can_be_marked_as_having_left(
    db_client: TestClient, console: ConsoleUsers, somebody: uuid.UUID
) -> None:
    """The control has to work, or the guards below are just breakage."""
    response = db_client.patch(
        f"/api/users/{somebody}", json={"active": False}, headers=console.as_admin
    )

    assert response.status_code == 200, response.text[:300]
    assert response.json()["active"] is False
    assert active_of(somebody) is False


def test_they_can_be_brought_back(
    db_client: TestClient, console: ConsoleUsers, somebody: uuid.UUID
) -> None:
    db_client.patch(f"/api/users/{somebody}", json={"active": False}, headers=console.as_admin)

    back = db_client.patch(
        f"/api/users/{somebody}", json={"active": True}, headers=console.as_admin
    )

    assert back.status_code == 200
    assert active_of(somebody) is True


# ----------------------------------------------------------------- yourself


def test_you_cannot_mark_yourself_as_having_left(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """The one that would end the session making the request."""
    me = console.id_of(console.admin)

    refused = db_client.patch(f"/api/users/{me}", json={"active": False}, headers=console.as_admin)

    assert refused.status_code == 409, refused.text[:300]
    assert "yourself" in refused.text
    assert active_of(me) is True


def test_the_refusal_says_what_it_would_have_done(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """Not just "no". Somebody who wanted this needs to know why it is refused and
    what to do instead, or they will reach for the database."""
    me = console.id_of(console.admin)

    refused = db_client.patch(f"/api/users/{me}", json={"active": False}, headers=console.as_admin)

    assert "end your sessions" in refused.text
    assert "Ask another admin" in refused.text


def test_somebody_who_is_not_an_admin_also_cannot_deactivate_themselves(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """The guard is about the request coming from the person it affects, not about
    their role. Helpdesk holds users:write, so without this they could do it."""
    helpdesk_id = console.id_of(console.helpdesk)

    refused = db_client.patch(
        f"/api/users/{helpdesk_id}",
        json={"active": False},
        headers=console.as_user(console.helpdesk),
    )

    assert refused.status_code == 409
    assert active_of(helpdesk_id) is True


def test_you_may_still_change_your_own_other_fields(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """The guard is narrow on purpose: only `active: false`, only for yourself."""
    me = console.id_of(console.admin)

    response = db_client.patch(
        f"/api/users/{me}", json={"job_title": "Platform Engineer"}, headers=console.as_admin
    )

    assert response.status_code == 200
    assert response.json()["job_title"] == "Platform Engineer"


def test_reactivating_yourself_is_not_refused(db_client: TestClient, console: ConsoleUsers) -> None:
    """Only `active: false` is dangerous. Sending true is a no-op for somebody who is
    already active, and refusing it would be a rule with no purpose."""
    me = console.id_of(console.admin)

    response = db_client.patch(f"/api/users/{me}", json={"active": True}, headers=console.as_admin)

    assert response.status_code == 200


# --------------------------------------------------------------- the last admin


def test_the_last_admin_cannot_be_marked_as_having_left(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """Deactivating an admin empties the set of people who can grant anything, exactly
    as revoking their grant would — and that door was already shut.

    Asked by helpdesk rather than by the admin themselves. Helpdesk holds users:write,
    so they are allowed to deactivate people, and routing the request through somebody
    else is what makes this test about the last-admin rule instead of the
    self-deactivation one. The first version had the admin target themselves and passed
    for entirely the wrong reason.
    """
    admin_id = console.id_of(console.admin)

    refused = db_client.patch(
        f"/api/users/{admin_id}",
        json={"active": False},
        headers=console.as_user(console.helpdesk),
    )

    assert refused.status_code == 409, refused.text[:300]
    assert "only admin left" in refused.text
    assert active_of(admin_id) is True


def test_an_admin_can_be_deactivated_while_another_one_exists(
    db_client: TestClient, console: ConsoleUsers, somebody: uuid.UUID
) -> None:
    """The other side of the rule: it refuses the *last* admin, not any admin."""
    admin_id = console.id_of(console.admin)
    now = dt.datetime.now(dt.UTC)

    async def promote(session: AsyncSession) -> None:
        person = await session.get(User, somebody)
        assert person is not None
        await grant_role(
            session,
            person,
            role=PlatformRole.ADMIN,
            granter=BOOTSTRAP,
            reason="a second admin, so the first is not the last",
            now=now,
        )
        await session.commit()

    run_db(promote)
    assert run_db(lambda s: count_live_admins(s, now=dt.datetime.now(dt.UTC))) >= 2

    allowed = db_client.patch(
        f"/api/users/{admin_id}",
        json={"active": False},
        headers=console.as_user(console.helpdesk),
    )

    assert allowed.status_code == 200, allowed.text[:300]
    assert active_of(admin_id) is False


def test_a_non_admin_can_be_deactivated_even_when_they_are_the_only_one_of_their_kind(
    db_client: TestClient, console: ConsoleUsers, somebody: uuid.UUID
) -> None:
    """The rule is about admins, not about being the last of anything."""
    response = db_client.patch(
        f"/api/users/{somebody}", json={"active": False}, headers=console.as_admin
    )

    assert response.status_code == 200


def test_a_deactivated_admin_stops_counting_towards_the_last_admin_rule(
    console: ConsoleUsers, somebody: uuid.UUID
) -> None:
    """The point of count_live_admins excluding inactive people.

    An admin who cannot sign in is no help when the last other admin is being removed,
    so they must not keep the count above one.
    """
    now = dt.datetime.now(dt.UTC)

    async def promote(session: AsyncSession) -> None:
        person = await session.get(User, somebody)
        assert person is not None
        await grant_role(
            session, person, role=PlatformRole.ADMIN, granter=BOOTSTRAP, reason="x", now=now
        )
        await session.commit()

    run_db(promote)
    before = run_db(lambda s: count_live_admins(s, now=now))

    async def deactivate(session: AsyncSession) -> None:
        person = await session.get(User, somebody)
        assert person is not None
        person.active = False
        await session.commit()

    run_db(deactivate)
    after = run_db(lambda s: count_live_admins(s, now=now))

    assert after == before - 1


# --------------------------------------------- telling somebody the set is empty


def test_the_dashboard_counts_live_admins(db_client: TestClient, console: ConsoleUsers) -> None:
    """So the console can say "nobody can administer this" instead of only failing.

    Counted from the grants rather than users.platform_role, which is a cache. This
    number is the difference between "somebody can fix this" and "somebody needs a
    shell", so it must not depend on a cache being right.
    """
    counts = db_client.get("/api/dashboard", headers=console.as_admin)

    assert counts.status_code == 200
    assert counts.json()["live_admins"] >= 1


def test_a_deactivated_admin_does_not_count(db_client: TestClient, console: ConsoleUsers) -> None:
    """The case that locked this deployment out.

    Okta deactivated the only admin, which revoked the grant. An admin who cannot
    sign in is no help, so they must not keep the number above zero and make the
    console look healthy.
    """
    before = db_client.get("/api/dashboard", headers=console.as_admin).json()["live_admins"]

    admin_id = console.id_of(console.admin)

    async def deactivate(session: AsyncSession) -> None:
        person = await session.get(User, admin_id)
        assert person is not None
        person.active = False
        await session.commit()

    run_db(deactivate)

    # Asked as helpdesk, because the admin can no longer do anything.
    after = db_client.get("/api/dashboard", headers=console.as_user(console.helpdesk)).json()[
        "live_admins"
    ]

    assert after == before - 1
