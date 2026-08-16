"""Tests for managing provisioning tokens from the console.

The two that matter: a token is shown exactly once and is never retrievable
afterwards, and revoking one actually stops it working. Everything else on this
screen is reporting.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.models.scim import ScimClient
from iam.security.tokens import hash_token
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration

CLIENTS = "/api/provisioning/clients"


def issue(client: TestClient, console: ConsoleUsers, name: str, **extra: Any) -> dict[str, Any]:
    response = client.post(CLIENTS, json={"name": name, **extra}, headers=console.as_admin)
    assert response.status_code == 201, response.text[:300]
    created: dict[str, Any] = response.json()
    return created


def cleanup(name: str) -> None:
    async def work(session: AsyncSession) -> None:
        await session.execute(delete(ScimClient).where(ScimClient.name == name))

    run_db(work)


# ------------------------------------------------------------ issuing tokens


def test_issuing_hands_back_a_token_once(db_client: TestClient, console: ConsoleUsers) -> None:
    name = f"issued-{console.suffix}"
    try:
        created = issue(db_client, console, name, description="for a test")

        assert created["token"]
        assert created["name"] == name
        assert created["usable"] is True

        # And nothing can fetch it again, because there is nothing to fetch.
        listed = db_client.get(CLIENTS, headers=console.as_admin).json()
        mine = next(row for row in listed if row["name"] == name)
        assert "token" not in mine
    finally:
        cleanup(name)


def test_only_the_hash_is_stored(db_client: TestClient, console: ConsoleUsers) -> None:
    """Somebody who reads the table cannot use what they find."""
    name = f"hashed-{console.suffix}"
    try:
        created = issue(db_client, console, name)

        async def work(session: AsyncSession) -> ScimClient | None:
            found: ScimClient | None = await session.scalar(
                select(ScimClient).where(ScimClient.name == name)
            )
            return found

        stored = run_db(work)
        assert stored is not None
        assert stored.token_hash == hash_token(created["token"])
        assert created["token"] not in stored.token_hash
    finally:
        cleanup(name)


def test_the_new_token_works_immediately(db_client: TestClient, console: ConsoleUsers) -> None:
    """Issuing it in the console and using it on the SCIM endpoint are the same
    credential — worth checking, since one writes the hash and the other reads it."""
    name = f"usable-{console.suffix}"
    try:
        created = issue(db_client, console, name)

        response = db_client.get(
            "/scim/v2/Users",
            params={"count": 1},
            headers={"Authorization": f"Bearer {created['token']}"},
        )

        assert response.status_code == 200
    finally:
        cleanup(name)


def test_two_clients_cannot_share_a_name(db_client: TestClient, console: ConsoleUsers) -> None:
    """The audit log names the client that acted, so duplicates make it ambiguous."""
    name = f"dupe-{console.suffix}"
    try:
        issue(db_client, console, name)

        again = db_client.post(CLIENTS, json={"name": name}, headers=console.as_admin)

        assert again.status_code == 409
    finally:
        cleanup(name)


def test_issuing_is_recorded_without_the_token(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """Logging the token would rather defeat the point of not storing it."""
    name = f"audited-{console.suffix}"
    try:
        created = issue(db_client, console, name)

        async def work(session: AsyncSession) -> AuditEvent | None:
            found: AuditEvent | None = await session.scalar(
                select(AuditEvent)
                .where(AuditEvent.action == "scim_client.issued")
                .order_by(AuditEvent.id.desc())
                .limit(1)
            )
            return found

        event = run_db(work)
        assert event is not None
        assert event.target_label == name
        assert console.admin in event.actor_label
        assert created["token"] not in str(event.detail)
    finally:
        cleanup(name)


# ---------------------------------------------------------------- revoking


def test_revoking_stops_the_token_working(db_client: TestClient, console: ConsoleUsers) -> None:
    """The point of the screen. A revoke that leaves the credential working is
    worse than no button at all, because somebody believes they cut it off."""
    name = f"revoked-{console.suffix}"
    try:
        created = issue(db_client, console, name)
        headers = {"Authorization": f"Bearer {created['token']}"}
        assert (
            db_client.get("/scim/v2/Users", params={"count": 1}, headers=headers).status_code == 200
        )

        response = db_client.post(
            f"{CLIENTS}/{created['id']}/revoke",
            json={"reason": "leaked in a screenshot"},
            headers=console.as_admin,
        )

        assert response.status_code == 200
        assert response.json()["usable"] is False
        assert response.json()["revoked_reason"] == "leaked in a screenshot"

        assert db_client.get("/scim/v2/Users", headers=headers).status_code == 401
    finally:
        cleanup(name)


def test_a_revoked_client_is_kept_not_deleted(db_client: TestClient, console: ConsoleUsers) -> None:
    """ "That sync stopped on the 3rd because we revoked it" has to stay
    answerable, and the audit entries referring to it still have to resolve."""
    name = f"kept-{console.suffix}"
    try:
        created = issue(db_client, console, name)
        db_client.post(f"{CLIENTS}/{created['id']}/revoke", json={}, headers=console.as_admin)

        listed = db_client.get(CLIENTS, headers=console.as_admin).json()
        mine = next(row for row in listed if row["name"] == name)

        assert mine["revoked_at"] is not None
    finally:
        cleanup(name)


def test_revoking_twice_keeps_the_first_reason(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """When it was cut off is the fact that matters."""
    name = f"twice-{console.suffix}"
    try:
        created = issue(db_client, console, name)
        first = db_client.post(
            f"{CLIENTS}/{created['id']}/revoke",
            json={"reason": "the real reason"},
            headers=console.as_admin,
        ).json()
        second = db_client.post(
            f"{CLIENTS}/{created['id']}/revoke",
            json={"reason": "a later guess"},
            headers=console.as_admin,
        ).json()

        assert second["revoked_reason"] == "the real reason"
        assert second["revoked_at"] == first["revoked_at"]
    finally:
        cleanup(name)


def test_revoking_something_that_is_not_there(db_client: TestClient, console: ConsoleUsers) -> None:
    import uuid

    response = db_client.post(f"{CLIENTS}/{uuid.uuid4()}/revoke", json={}, headers=console.as_admin)

    assert response.status_code == 404


# ------------------------------------------------------------- who can do it


def test_an_auditor_can_see_the_tokens_but_not_issue_one(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """ "Is the sync running" is a question an auditor should be able to answer.
    "Here is a new credential" is not a sentence they should be able to say."""
    assert db_client.get(CLIENTS, headers=console.as_user(console.auditor)).status_code == 200

    denied = db_client.post(
        CLIENTS, json={"name": f"nope-{console.suffix}"}, headers=console.as_user(console.auditor)
    )

    assert denied.status_code == 403


def test_an_employee_cannot_see_them_at_all(db_client: TestClient, console: ConsoleUsers) -> None:
    response = db_client.get(CLIENTS, headers=console.as_user(console.employee))

    assert response.status_code == 403


# ------------------------------------------------------------- the overview


def test_the_overview_counts_what_the_sync_owns(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    response = db_client.get("/api/provisioning/overview", headers=console.as_admin)
    document = response.json()

    assert response.status_code == 200
    assert document["users_from_scim"] >= 0
    assert document["groups_from_scim"] >= 0
    assert document["active_clients"] >= 0


def test_the_activity_list_only_shows_provisioning(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """It is a view over the audit log, not a second copy of it. A console edit
    turning up here would make the screen useless for its one job."""
    response = db_client.get("/api/provisioning/activity", headers=console.as_admin)

    assert response.status_code == 200
    for entry in response.json():
        assert entry["client"], "every entry here should name the client that did it"
