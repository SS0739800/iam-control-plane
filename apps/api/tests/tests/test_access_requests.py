"""Tests for access requests and approvals.

The one that matters most is that nobody can decide their own request. An approval
step you can perform on yourself is a form filled in twice, and every other
control here assumes it means something. It is checked in the service layer and
constrained in the database, so both are tested.

After that: approving actually grants the access — an approval that records a
decision without acting on it leaves somebody waiting for something they were told
they had — and decisions are final.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access import Granter, cut_access
from iam.models.enums import IdentitySource, MembershipSource, RequestState
from iam.models.group import Group, GroupMember
from iam.models.requests import AccessRequest
from iam.models.user import User
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration

REQUESTS = "/api/access-requests"


@pytest.fixture
def group(console: ConsoleUsers) -> Any:
    """A group people can ask for, cleaned up afterwards."""

    async def create(session: AsyncSession) -> uuid.UUID:
        made = Group(name=f"requestable-{console.suffix}", source=IdentitySource.MANUAL)
        session.add(made)
        await session.flush()
        return made.id

    group_id = run_db(create)
    yield group_id

    async def remove(session: AsyncSession) -> None:
        await session.execute(delete(AccessRequest).where(AccessRequest.group_id == group_id))
        await session.execute(delete(GroupMember).where(GroupMember.group_id == group_id))
        await session.execute(delete(Group).where(Group.id == group_id))

    run_db(remove)


def ask(
    client: TestClient,
    who: str,
    group_id: uuid.UUID,
    reason: str = "I need it for a project",
) -> httpx.Response:
    return client.post(
        REQUESTS,
        json={"group_id": str(group_id), "reason": reason},
        headers={"X-Dev-Actor": who},
    )


def members_of(group_id: uuid.UUID) -> dict[str, MembershipSource]:
    async def work(session: AsyncSession) -> dict[str, MembershipSource]:
        rows = await session.execute(
            select(User.user_name, GroupMember.source)
            .join(GroupMember, GroupMember.user_id == User.id)
            .where(GroupMember.group_id == group_id)
        )
        return dict(rows.tuples().all())

    return run_db(work)


def deactivate(user_id: uuid.UUID) -> None:
    async def work(session: AsyncSession) -> None:
        person = await session.get(User, user_id)
        assert person is not None
        person.active = False

    run_db(work)


# ------------------------------------------------------------------- asking


def test_an_employee_can_ask(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """An employee holds no permissions at all. A request system only they cannot
    use is not a request system."""
    response = ask(db_client, console.employee, group)

    assert response.status_code == 201, response.text[:300]
    assert response.json()["state"] == "pending"
    assert response.json()["is_open"] is True


def test_a_reason_is_required(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """An approver with no reason in front of them is rubber-stamping."""
    response = ask(db_client, console.employee, group, reason="   ")

    assert response.status_code in (400, 422)


def test_asking_twice_is_refused(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Two approvals of the same thing would look like two decisions."""
    ask(db_client, console.employee, group)

    again = ask(db_client, console.employee, group)

    assert again.status_code == 400
    assert "already an open request" in again.json()["detail"]


def test_asking_for_something_you_already_have_is_refused(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    employee_id = console.id_of(console.employee)

    async def add(session: AsyncSession) -> None:
        session.add(
            GroupMember(group_id=group, user_id=employee_id, source=MembershipSource.MANUAL)
        )

    run_db(add)

    response = ask(db_client, console.employee, group)

    assert response.status_code == 400
    assert "already in" in response.json()["detail"]


def test_you_can_always_see_your_own_requests(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    ask(db_client, console.employee, group)

    mine = db_client.get(f"{REQUESTS}/mine", headers=console.as_user(console.employee))

    assert mine.status_code == 200
    assert len(mine.json()) == 1


def test_an_employee_cannot_read_the_queue(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Who has been asking for the finance system is review information, not public."""
    response = db_client.get(REQUESTS, headers=console.as_user(console.employee))

    assert response.status_code == 403


# --------------------------------------------------- nobody decides their own


def test_you_cannot_approve_your_own_request(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """The rule that makes the whole approval step worth having."""
    raised = ask(db_client, console.admin, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve", json={}, headers=console.as_admin
    )

    assert response.status_code == 400
    assert "your own access request" in response.json()["detail"]
    assert members_of(group) == {}


def test_you_cannot_deny_your_own_request_either(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    raised = ask(db_client, console.admin, group).json()

    response = db_client.post(f"{REQUESTS}/{raised['id']}/deny", json={}, headers=console.as_admin)

    assert response.status_code == 400


def test_the_database_refuses_a_self_decision(console: ConsoleUsers, group: uuid.UUID) -> None:
    """Going around the service layer on purpose.

    A rule that lives only in application code is one refactor away from not
    existing, so this one is a CHECK constraint as well.

    Written as a sync test running its own transaction, because run_db calls
    asyncio.run and so cannot be used from inside an async test.
    """
    admin_id = console.id_of(console.admin)

    async def attempt(session: AsyncSession) -> None:
        session.add(
            AccessRequest(
                requester_id=admin_id,
                requester_label="somebody",
                group_id=group,
                group_label="a group",
                reason="because",
                state=RequestState.APPROVED,
                decided_by_id=admin_id,
                decided_by_label="the very same somebody",
                decided_at=dt.datetime.now(dt.UTC),
            )
        )
        await session.flush()

    with pytest.raises(IntegrityError):
        run_db(attempt)


def test_an_employee_cannot_approve(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve",
        json={},
        headers=console.as_user(console.employee),
    )

    assert response.status_code == 403


def test_helpdesk_cannot_approve(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Approving is group membership with a paper trail, and helpdesk cannot change
    group membership."""
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve",
        json={},
        headers=console.as_user(console.helpdesk),
    )

    assert response.status_code == 403


# ----------------------------------------------------------------- deciding


def test_approving_actually_grants_the_access(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """An approval that records a decision without granting the access leaves
    somebody waiting for something they were told they had."""
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve",
        json={"note": "Fine for this quarter"},
        headers=console.as_admin,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "approved"
    assert console.admin in body["decided_by_label"]
    assert body["decision_note"] == "Fine for this quarter"

    # In the group, and recorded as approved rather than added by hand — a review
    # asking "why is this person in here" should get the more specific answer.
    assert members_of(group) == {console.employee: MembershipSource.REQUEST}


def test_denying_records_it_and_grants_nothing(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/deny",
        json={"note": "Ask your manager first"},
        headers=console.as_admin,
    )

    assert response.status_code == 200
    assert response.json()["state"] == "denied"
    assert members_of(group) == {}


def test_a_decision_is_final(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """A request that could reopen would make "who approved this" ambiguous."""
    raised = ask(db_client, console.employee, group).json()
    db_client.post(f"{REQUESTS}/{raised['id']}/deny", json={}, headers=console.as_admin)

    again = db_client.post(f"{REQUESTS}/{raised['id']}/approve", json={}, headers=console.as_admin)

    assert again.status_code == 400
    assert "already" in again.json()["detail"]


def test_a_refused_request_can_be_raised_again(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Two requests, honestly recorded as two, rather than one that reopened."""
    raised = ask(db_client, console.employee, group).json()
    db_client.post(f"{REQUESTS}/{raised['id']}/deny", json={}, headers=console.as_admin)

    second = ask(db_client, console.employee, group, reason="Trying again with my manager's ok")

    assert second.status_code == 201
    history = db_client.get(f"{REQUESTS}/mine", headers=console.as_user(console.employee)).json()
    assert len(history) == 2


def test_temporary_access_keeps_its_end_date(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """A system that can only grant forever turns every temporary need into
    permanent access."""
    raised = ask(db_client, console.employee, group).json()
    until = dt.datetime.now(dt.UTC) + dt.timedelta(days=90)

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve",
        json={"expires_at": until.isoformat()},
        headers=console.as_admin,
    )

    assert response.status_code == 200
    assert response.json()["expires_at"] is not None


def test_an_expiry_in_the_past_is_refused(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    raised = ask(db_client, console.employee, group).json()
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve",
        json={"expires_at": past.isoformat()},
        headers=console.as_admin,
    )

    assert response.status_code == 400


# -------------------------------------------------------------- withdrawing


def test_you_can_withdraw_your_own(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/withdraw", headers=console.as_user(console.employee)
    )

    assert response.status_code == 200
    assert response.json()["state"] == "withdrawn"


def test_somebody_else_cannot_withdraw_it(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Them closing it is a denial. The record should say which of the two happened."""
    raised = ask(db_client, console.employee, group).json()

    response = db_client.post(f"{REQUESTS}/{raised['id']}/withdraw", headers=console.as_admin)

    assert response.status_code == 403


# ------------------------------------------------------- overlap with leaving


def test_a_leaver_has_their_open_requests_cancelled(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Otherwise their requests sit in the queue and somebody approves one months
    later without noticing the requester is gone."""
    raised = ask(db_client, console.employee, group).json()
    employee_id = console.id_of(console.employee)

    async def leave(session: AsyncSession) -> None:
        person = await session.get(User, employee_id)
        assert person is not None
        person.active = False
        await cut_access(
            session,
            person,
            by=Granter(user_id=None, label="the test"),
            now=dt.datetime.now(dt.UTC),
        )

    run_db(leave)

    after = db_client.get(f"{REQUESTS}/{raised['id']}", headers=console.as_admin).json()

    assert after["state"] == "cancelled"
    # Cancelled, not denied. Nobody weighed it and said no; it stopped being a
    # question.
    assert after["decided_by_label"] is None


def test_a_deactivated_requester_cannot_be_approved(
    db_client: TestClient, console: ConsoleUsers, group: uuid.UUID
) -> None:
    """Approving access for somebody who has left is how a leaver keeps a foothold."""
    raised = ask(db_client, console.employee, group).json()
    deactivate(console.id_of(console.employee))

    response = db_client.post(
        f"{REQUESTS}/{raised['id']}/approve", json={}, headers=console.as_admin
    )

    assert response.status_code == 400
    assert "deactivated" in response.json()["detail"]
