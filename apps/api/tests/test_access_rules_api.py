"""Tests for the rules API, and for the rules actually running when they should.

The engine has its own tests. These check the wiring, which is where a rule engine
usually turns out to be broken: it works when you call it and nothing calls it.

So the important ones here drive the real endpoints — a SCIM PATCH that changes
somebody's department, a console edit that does the same — and check the group
membership followed.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import IdentitySource, MembershipSource, PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.rules import AccessRule
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.tokens import hash_token, new_token
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration

RULES = "/api/access-rules"


@pytest.fixture
def group(console: ConsoleUsers) -> Any:
    """A group for rules to point at, cleaned up afterwards."""
    name = f"rules-target-{console.suffix}"

    async def create(session: AsyncSession) -> uuid.UUID:
        made = Group(name=name, source=IdentitySource.MANUAL)
        session.add(made)
        await session.flush()
        return made.id

    group_id = run_db(create)
    yield group_id

    async def remove(session: AsyncSession) -> None:
        await session.execute(delete(AccessRule).where(AccessRule.group_id == group_id))
        await session.execute(delete(GroupMember).where(GroupMember.group_id == group_id))
        await session.execute(delete(Group).where(Group.id == group_id))

    run_db(remove)


@pytest.fixture
def person(console: ConsoleUsers) -> Any:
    """Somebody with a department, for rules to match."""
    suffix = uuid.uuid4().hex[:12]

    async def create(session: AsyncSession) -> uuid.UUID:
        made = User(
            user_name=f"wired.{suffix}@demo.local",
            email=f"wired.{suffix}@demo.local",
            display_name=f"Wired Tester {suffix}",
            active=True,
            department="Engineering",
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.SCIM,
        )
        session.add(made)
        await session.flush()
        return made.id

    user_id = run_db(create)
    yield user_id

    async def remove(session: AsyncSession) -> None:
        await session.execute(delete(GroupMember).where(GroupMember.user_id == user_id))
        await session.execute(delete(User).where(User.id == user_id))

    run_db(remove)


@pytest.fixture
def scim_token(console: ConsoleUsers) -> Any:
    name = f"rules-wiring-{console.suffix}"
    token = new_token()

    async def create(session: AsyncSession) -> None:
        session.add(ScimClient(name=name, token_hash=hash_token(token), enabled=True))

    run_db(create)
    yield token

    async def remove(session: AsyncSession) -> None:
        await session.execute(delete(ScimClient).where(ScimClient.name == name))

    run_db(remove)


def groups_of(user_id: uuid.UUID) -> dict[str, MembershipSource]:
    async def work(session: AsyncSession) -> dict[str, MembershipSource]:
        rows = await session.execute(
            select(Group.name, GroupMember.source)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user_id)
        )
        return dict(rows.tuples().all())

    return run_db(work)


def make_rule(
    client: TestClient, console: ConsoleUsers, group_id: uuid.UUID, **overrides: Any
) -> dict[str, Any]:
    body = {
        "name": f"engineering-{uuid.uuid4().hex[:8]}",
        "attribute": "department",
        "operator": "equals",
        "value": "Engineering",
        "group_id": str(group_id),
    }
    body.update(overrides)
    response = client.post(RULES, json=body, headers=console.as_admin)
    assert response.status_code == 201, response.text[:300]
    created: dict[str, Any] = response.json()
    return created


# ----------------------------------------------------------- who may write one


def test_helpdesk_cannot_write_a_rule(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """A rule is automated group membership, so it needs the permission that lets
    somebody change group membership — which helpdesk does not have."""
    response = db_client.post(
        RULES,
        json={
            "name": "nope",
            "attribute": "department",
            "operator": "equals",
            "value": "Engineering",
            "group_id": str(group),
        },
        headers=console.as_user(console.helpdesk),
    )

    assert response.status_code == 403
    assert "groups:write" in response.json()["detail"]


def test_an_auditor_can_read_rules(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    assert db_client.get(RULES, headers=console.as_user(console.auditor)).status_code == 200


# --------------------------------------------------------------- writing rules


def test_creating_a_rule_applies_it_immediately(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """A rule that only took effect on somebody's next department change would look
    broken for weeks."""
    make_rule(db_client, console, group)

    assert list(groups_of(person).values()) == [MembershipSource.RULE]


def test_the_rule_comes_back_as_a_sentence(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    created = make_rule(db_client, console, group)

    assert created["sentence"] == "Department is 'Engineering'"


def test_a_rule_cannot_read_a_field_it_should_not(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    response = db_client.post(
        RULES,
        json={
            "name": "sneaky",
            "attribute": "platform_role",
            "operator": "equals",
            "value": "admin",
            "group_id": str(group),
        },
        headers=console.as_admin,
    )

    assert response.status_code == 400
    assert "can't look at" in response.json()["detail"]


def test_the_same_condition_twice_is_refused(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    make_rule(db_client, console, group)

    again = db_client.post(
        RULES,
        json={
            "name": "a-different-name",
            "attribute": "department",
            "operator": "equals",
            "value": "Engineering",
            "group_id": str(group),
        },
        headers=console.as_admin,
    )

    assert again.status_code == 409


def test_disabling_a_rule_takes_back_what_it_granted(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """The only reading of "disabled" that means anything."""
    created = make_rule(db_client, console, group)
    assert groups_of(person)

    response = db_client.patch(
        f"{RULES}/{created['id']}", json={"enabled": False}, headers=console.as_admin
    )

    assert response.status_code == 200
    assert groups_of(person) == {}


def test_deleting_a_rule_removes_the_access_it_gave(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """Leaving the memberships behind would turn automatic access into permanent
    access that nothing explains."""
    created = make_rule(db_client, console, group)
    assert groups_of(person)

    response = db_client.delete(f"{RULES}/{created['id']}", headers=console.as_admin)

    assert response.status_code == 200
    assert groups_of(person) == {}


def test_running_a_rule_again_reports_no_change(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """The answer you want from a re-run."""
    created = make_rule(db_client, console, group)

    response = db_client.post(f"{RULES}/{created['id']}/run", headers=console.as_admin)

    assert response.status_code == 200
    assert response.json()["unchanged"] is True


# ------------------------------------------------------------------ previewing


def test_preview_says_who_would_be_affected_and_writes_nothing(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """A condition that reads correctly and matches four hundred people usually
    means the value was mistyped. This is where that gets noticed."""
    response = db_client.post(
        f"{RULES}/preview",
        json={
            "name": "not-saved",
            "attribute": "department",
            "operator": "equals",
            "value": "Engineering",
            "group_id": str(group),
        },
        headers=console.as_admin,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["matches"] >= 1
    assert body["would_be_added"] >= 1
    assert body["sentence"] == "Department is 'Engineering'"

    # Nothing was saved, and nobody was moved.
    assert db_client.get(RULES, headers=console.as_admin).json() == []
    assert groups_of(person) == {}


# ------------------------------------------------------ the wiring that matters


def test_a_scim_department_change_moves_their_groups(
    db_client: TestClient,
    console: ConsoleUsers,
    group: uuid.UUID,
    person: uuid.UUID,
    scim_token: str,
) -> None:
    """The mover case arriving the way it actually arrives.

    Somebody's department changes in the HR system, the provider syncs it, and
    their group membership has to follow. This is the test that would fail if the
    engine existed but nothing called it.
    """
    make_rule(db_client, console, group)
    assert list(groups_of(person).values()) == [MembershipSource.RULE]

    moved = db_client.patch(
        f"/scim/v2/Users/{person}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "department", "value": "Sales"}],
        },
        headers={"Authorization": f"Bearer {scim_token}"},
    )

    assert moved.status_code == 200, moved.text[:300]
    assert groups_of(person) == {}


def test_a_console_department_change_moves_their_groups(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """Editing somebody here has the same consequence as the provider doing it.
    Otherwise the console is a way to move departments and leave the groups behind.
    """
    make_rule(db_client, console, group)
    assert list(groups_of(person).values()) == [MembershipSource.RULE]

    # The user came from SCIM, so department is provider-owned and the console
    # refuses to edit it. Take that away first — this test is about the rules
    # firing, not about who owns the field.
    async def make_manual(session: AsyncSession) -> None:
        found = await session.get(User, person)
        assert found is not None
        found.source = IdentitySource.MANUAL

    run_db(make_manual)

    moved = db_client.patch(
        f"/api/users/{person}", json={"department": "Sales"}, headers=console.as_admin
    )

    assert moved.status_code == 200, moved.text[:300]
    assert groups_of(person) == {}


def test_a_change_no_rule_reads_does_not_reshuffle_anything(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID, person: uuid.UUID
) -> None:
    """The gate. A provider re-syncing a display name should not run the engine for
    every person on every sync."""
    make_rule(db_client, console, group)

    async def make_manual(session: AsyncSession) -> None:
        found = await session.get(User, person)
        assert found is not None
        found.source = IdentitySource.MANUAL

    run_db(make_manual)

    changed = db_client.patch(
        f"/api/users/{person}", json={"job_title": "Staff Engineer"}, headers=console.as_admin
    )

    assert changed.status_code == 200
    # Still in the group: nothing a rule reads moved.
    assert list(groups_of(person).values()) == [MembershipSource.RULE]
