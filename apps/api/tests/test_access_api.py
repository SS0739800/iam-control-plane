"""Tests for the grant and revoke endpoints.

Two of these matter more than the rest.

Helpdesk must not be able to grant roles. They hold users:write, so if granting
were an ordinary user edit they could promote themselves, and the whole permission
table would be decoration.

The last admin must not be removable. There is no root account here, so an empty
admin set is unrecoverable except by hand-editing the database — which is the
thing this endpoint exists to replace.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.access import RoleGrant
from iam.models.audit import AuditEvent
from iam.models.enums import IdentitySource, PlatformRole
from iam.models.user import User
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration


def make_person(suffix: str) -> uuid.UUID:
    """Somebody to be granted things, created outside the request."""

    async def work(session: AsyncSession) -> uuid.UUID:
        user = User(
            user_name=f"subject.{suffix}@demo.local",
            email=f"subject.{suffix}@demo.local",
            display_name=f"Subject {suffix}",
            active=True,
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.MANUAL,
        )
        session.add(user)
        await session.flush()
        return user.id

    return run_db(work)


def remove_person(user_id: uuid.UUID) -> None:
    async def work(session: AsyncSession) -> None:
        await session.execute(delete(RoleGrant).where(RoleGrant.user_id == user_id))
        await session.execute(delete(User).where(User.id == user_id))

    run_db(work)


@pytest.fixture
def subject(console: ConsoleUsers) -> Any:
    """A throwaway person, cleaned up afterwards."""
    user_id = make_person(uuid.uuid4().hex[:12])
    yield user_id
    remove_person(user_id)


def grants_url(user_id: uuid.UUID) -> str:
    return f"/api/users/{user_id}/role-grants"


# ------------------------------------------------------- who may grant a role


def test_helpdesk_cannot_grant_a_role(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """The one that stops the permission table being decoration.

    Helpdesk can edit users. If that were enough to grant a role, anybody who can
    fix a misspelled name could make themselves an admin.
    """
    response = db_client.post(
        grants_url(subject),
        json={"role": "admin"},
        headers=console.as_user(console.helpdesk),
    )

    assert response.status_code == 403
    assert "roles:write" in response.json()["detail"]


def test_helpdesk_cannot_promote_themselves(db_client: TestClient, console: ConsoleUsers) -> None:
    """The same hole, aimed at the obvious target."""
    helpdesk_id = console.id_of(console.helpdesk)

    response = db_client.post(
        grants_url(helpdesk_id),
        json={"role": "admin"},
        headers=console.as_user(console.helpdesk),
    )

    assert response.status_code == 403


def test_an_auditor_can_read_grants_but_not_make_them(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """Reviewing access and granting it are different jobs."""
    assert (
        db_client.get(grants_url(subject), headers=console.as_user(console.auditor)).status_code
        == 200
    )

    denied = db_client.post(
        grants_url(subject), json={"role": "auditor"}, headers=console.as_user(console.auditor)
    )

    assert denied.status_code == 403


def test_an_employee_cannot_even_look(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    response = db_client.get(grants_url(subject), headers=console.as_user(console.employee))

    assert response.status_code == 403


# ---------------------------------------------------------------- granting


def test_granting_a_role(db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID) -> None:
    response = db_client.post(
        grants_url(subject),
        json={"role": "helpdesk", "reason": "Joining the service desk"},
        headers=console.as_admin,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "helpdesk"
    assert body["reason"] == "Joining the service desk"
    assert body["live"] is True
    assert console.admin in body["granted_by_label"]


def test_granting_shows_up_in_the_access_summary(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    db_client.post(
        grants_url(subject),
        json={"role": "auditor", "reason": "Quarterly review"},
        headers=console.as_admin,
    )

    summary = db_client.get(f"/api/users/{subject}/access", headers=console.as_admin).json()

    assert summary["role"] == "auditor"
    assert console.admin in summary["role_granted_by"]
    assert len(summary["grant_history"]) == 1


def test_granting_with_an_expiry(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """Standing access nobody revisits is how an unnoticed admin happens."""
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)

    response = db_client.post(
        grants_url(subject),
        json={"role": "admin", "expires_at": expires.isoformat()},
        headers=console.as_admin,
    )

    assert response.status_code == 201
    assert response.json()["expires_at"] is not None


def test_an_expiry_in_the_past_is_refused(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)

    response = db_client.post(
        grants_url(subject),
        json={"role": "admin", "expires_at": past.isoformat()},
        headers=console.as_admin,
    )

    assert response.status_code == 400
    assert "already passed" in response.json()["detail"]


def test_granting_employee_is_refused(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    response = db_client.post(
        grants_url(subject), json={"role": "employee"}, headers=console.as_admin
    )

    assert response.status_code == 400
    assert "Revoke" in response.json()["detail"]


def test_granting_records_who_did_it(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """ "Who made whom an admin" is the first question asked after anything goes wrong."""
    db_client.post(grants_url(subject), json={"role": "admin"}, headers=console.as_admin)

    async def work(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "role.granted")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    event = run_db(work)
    assert event is not None
    assert console.admin in event.actor_label
    assert event.detail["role"] == "admin"
    assert event.detail["self_grant"] is False


# ---------------------------------------------------------------- revoking


def test_revoking_puts_them_back_to_employee(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    db_client.post(grants_url(subject), json={"role": "helpdesk"}, headers=console.as_admin)

    response = db_client.request(
        "DELETE", grants_url(subject), json={"reason": "left the team"}, headers=console.as_admin
    )

    assert response.status_code == 200
    assert response.json()["role"] == "employee"


def test_the_revoked_grant_stays_in_the_history(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    db_client.post(grants_url(subject), json={"role": "admin"}, headers=console.as_admin)
    db_client.request("DELETE", grants_url(subject), json={}, headers=console.as_admin)

    past = db_client.get(grants_url(subject), headers=console.as_admin).json()

    assert len(past) == 1
    assert past[0]["role"] == "admin"
    assert past[0]["live"] is False
    assert past[0]["revoked_at"] is not None


def test_revoking_nothing_is_not_an_error(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """The end state is what was asked for."""
    response = db_client.request("DELETE", grants_url(subject), json={}, headers=console.as_admin)

    assert response.status_code == 200
    assert response.json()["role"] == "employee"


def test_superseding_is_visible_in_the_history(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """Two decisions, both recorded, rather than one mutable fact."""
    db_client.post(grants_url(subject), json={"role": "helpdesk"}, headers=console.as_admin)
    db_client.post(grants_url(subject), json={"role": "auditor"}, headers=console.as_admin)

    past = db_client.get(grants_url(subject), headers=console.as_admin).json()

    assert len(past) == 2
    live = [row for row in past if row["live"]]
    assert len(live) == 1
    assert live[0]["role"] == "auditor"
    superseded = next(row for row in past if not row["live"])
    assert superseded["revoked_reason"] == "superseded"


# ------------------------------------------------------------ the last admin


def test_the_last_admin_cannot_be_revoked(db_client: TestClient, console: ConsoleUsers) -> None:
    """There is no root account, so an empty admin set can only be fixed by
    hand-editing the database — which is what this endpoint replaces."""
    admin_id = console.id_of(console.admin)

    response = db_client.request("DELETE", grants_url(admin_id), json={}, headers=console.as_admin)

    assert response.status_code == 409
    assert "only admin left" in response.json()["detail"]

    # And they really do still have it.
    summary = db_client.get(f"/api/users/{admin_id}/access", headers=console.as_admin).json()
    assert summary["role"] == "admin"


def test_the_last_admin_cannot_be_demoted_either(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """Granting a lesser role replaces the admin grant, so it is the same hole
    wearing a different hat."""
    admin_id = console.id_of(console.admin)

    response = db_client.post(
        grants_url(admin_id), json={"role": "auditor"}, headers=console.as_admin
    )

    assert response.status_code == 409
    assert "only admin left" in response.json()["detail"]


def test_an_admin_can_step_down_once_somebody_else_can_grant(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """The guard is about the set never emptying, not about protecting one person."""
    admin_id = console.id_of(console.admin)
    db_client.post(grants_url(subject), json={"role": "admin"}, headers=console.as_admin)

    response = db_client.request("DELETE", grants_url(admin_id), json={}, headers=console.as_admin)

    assert response.status_code == 200
    assert response.json()["role"] == "employee"

    # Put it back, so the rest of the suite still has its admin.
    db_client.post(
        grants_url(admin_id),
        json={"role": "admin", "reason": "restored by the test that stepped down"},
        headers=console.as_user(console.user_name_of(subject)),
    )
    restored = db_client.get(f"/api/users/{admin_id}/access", headers=console.as_admin).json()
    assert restored["role"] == "admin"


def test_a_deactivated_admin_does_not_count_as_cover(
    db_client: TestClient, console: ConsoleUsers, subject: uuid.UUID
) -> None:
    """They cannot sign in, so they are no help when the last active admin goes."""
    admin_id = console.id_of(console.admin)
    db_client.post(grants_url(subject), json={"role": "admin"}, headers=console.as_admin)

    async def deactivate(session: AsyncSession) -> None:
        person = await session.get(User, subject)
        assert person is not None
        person.active = False

    run_db(deactivate)

    response = db_client.request("DELETE", grants_url(admin_id), json={}, headers=console.as_admin)

    assert response.status_code == 409


# ---------------------------------------------------------------- not found


def test_granting_to_somebody_who_is_not_there(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    response = db_client.post(
        grants_url(uuid.uuid4()), json={"role": "admin"}, headers=console.as_admin
    )

    assert response.status_code == 404
