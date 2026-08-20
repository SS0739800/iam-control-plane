"""Tests for registering and running provisioning targets.

Three claims matter most.

The token is never returned. It is encrypted rather than hashed, so unlike an inbound
token we genuinely could hand it back — and that is exactly why no endpoint does.

The address rules from ADR 0007 are enforced at registration. Link-local is refused
with no way to allow it, because that is where cloud metadata services live.

Deleting a target does not deactivate anybody, and the audit entry says so with the
number of accounts left active downstream. A button that quietly switched off two
hundred accounts would be a much bigger action than it looks.

Needs Postgres and skips without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.application import Application
from iam.models.audit import AuditEvent
from iam.models.enums import AppProtocol, AppStatus
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from tests.saml_harness import ConsoleUsers
from tests.support import run_db

pytestmark = pytest.mark.integration

TARGETS = "/api/provisioning/targets"


@pytest.fixture
def application(console: ConsoleUsers) -> Any:
    """An application for a target to belong to."""
    slug = f"target-app-{console.suffix}"

    async def create(session: AsyncSession) -> uuid.UUID:
        app = Application(
            name=f"Target App {console.suffix}",
            slug=slug,
            protocol=AppProtocol.SCIM2,
            status=AppStatus.ACTIVE,
        )
        session.add(app)
        await session.flush()
        return app.id

    app_id = run_db(create)
    yield app_id

    async def remove(session: AsyncSession) -> None:
        targets = (
            await session.scalars(
                select(ProvisioningTarget.id).where(ProvisioningTarget.application_id == app_id)
            )
        ).all()
        if targets:
            await session.execute(
                delete(ProvisioningLink).where(ProvisioningLink.target_id.in_(targets))
            )
        await session.execute(
            delete(ProvisioningTarget).where(ProvisioningTarget.application_id == app_id)
        )
        await session.execute(delete(Application).where(Application.id == app_id))

    run_db(remove)


def register(
    client: TestClient,
    console: ConsoleUsers,
    app_id: uuid.UUID,
    *,
    base_url: str = "http://downstream.test/scim/v2",
    # Not a real credential; the downstream in these tests is a hostname that does
    # not resolve. ruff flags any default that looks like one.
    token: str = "a-downstream-token",  # noqa: S107
) -> Any:
    return client.post(
        TARGETS,
        json={"application_id": str(app_id), "base_url": base_url, "token": token},
        headers=console.as_admin,
    )


# ------------------------------------------------------------- registering


def test_registering_a_target(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    response = register(db_client, console, application)

    assert response.status_code == 201, response.text[:300]
    body = response.json()
    assert body["base_url"] == "http://downstream.test/scim/v2"
    assert body["enabled"] is True
    # Never synced, so the counts start empty rather than absent.
    assert body["last_sync_ok"] is None
    assert body["accounts_active"] == 0


def test_the_token_is_never_returned(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """It is encrypted rather than hashed, so we could hand it back. That is exactly
    why nothing does — a value that can be read back leaks through a screenshot."""
    created = register(db_client, console, application, token="super-secret-token").json()

    assert "token" not in created
    assert "token_encrypted" not in created
    assert "super-secret-token" not in str(created)

    listed = db_client.get(TARGETS, headers=console.as_admin).json()
    assert "super-secret-token" not in str(listed)


def test_the_token_really_is_encrypted_at_rest(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Somebody reading the table gets ciphertext, not a working credential."""
    register(db_client, console, application, token="plainly-visible")

    async def read(session: AsyncSession) -> str:
        target = await session.scalar(
            select(ProvisioningTarget).where(ProvisioningTarget.application_id == application)
        )
        assert target is not None
        return target.token_encrypted

    stored = run_db(read)

    assert "plainly-visible" not in stored
    from iam.secrets import looks_encrypted

    assert looks_encrypted(stored)


def test_plain_http_locally_records_the_concession(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Allowed outside production, and shown so it reads as a decision rather than
    something nobody noticed."""
    created = register(db_client, console, application, base_url="http://hrms:8000/scim/v2").json()

    assert created["address_concession"] is not None
    assert "HTTP" in created["address_concession"]


def test_the_metadata_service_is_refused(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """The one address rule with no way to relax it, because that is where a cloud
    metadata service hands out credentials to anything that asks."""
    response = register(db_client, console, application, base_url="http://169.254.169.254/scim/v2")

    assert response.status_code == 400
    assert "link-local" in response.json()["detail"]


def test_a_nonsense_scheme_is_refused(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    response = register(db_client, console, application, base_url="ftp://downstream.test/scim")

    assert response.status_code == 400


def test_one_target_per_application(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Two would race each other writing the same accounts."""
    register(db_client, console, application)

    again = register(db_client, console, application)

    assert again.status_code == 409
    assert "already has a provisioning target" in again.json()["detail"]


def test_registering_for_an_application_that_is_not_there(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    response = db_client.post(
        TARGETS,
        json={
            "application_id": str(uuid.uuid4()),
            "base_url": "https://downstream.test/scim/v2",
            "token": "t",
        },
        headers=console.as_admin,
    )

    assert response.status_code == 404


def test_the_concession_is_recorded_in_the_audit_log(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """A relaxed rule should be findable later, not only visible on a page somebody
    may never open."""
    register(db_client, console, application, base_url="http://hrms:8000/scim/v2")

    async def read(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "provisioning_target.registered")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    event = run_db(read)
    assert event is not None
    assert event.detail["address_concession"] is not None


# ------------------------------------------------------------ who may do it


def test_helpdesk_cannot_register_a_target(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Registering a target decides where our directory data goes."""
    response = db_client.post(
        TARGETS,
        json={
            "application_id": str(application),
            "base_url": "https://downstream.test/scim/v2",
            "token": "t",
        },
        headers=console.as_user(console.helpdesk),
    )

    assert response.status_code == 403
    assert "apps:write" in response.json()["detail"]


def test_an_auditor_can_see_targets(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """ "Is anything being pushed anywhere" is a question a reviewer should be able to
    answer."""
    register(db_client, console, application)

    response = db_client.get(TARGETS, headers=console.as_user(console.auditor))

    assert response.status_code == 200


def test_an_employee_cannot_see_targets(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    response = db_client.get(TARGETS, headers=console.as_user(console.employee))

    assert response.status_code == 403


# ---------------------------------------------------------------- updating


def test_rotating_the_token_clears_the_last_error(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """A new token makes the old failure stale, so it stops being shown."""
    created = register(db_client, console, application).json()

    async def break_it(session: AsyncSession) -> None:
        target = await session.get(ProvisioningTarget, uuid.UUID(created["id"]))
        assert target is not None
        target.last_error = "the old token was rejected"
        target.last_sync_ok = False

    run_db(break_it)

    response = db_client.patch(
        f"{TARGETS}/{created['id']}",
        json={"token": "a-fresh-token"},
        headers=console.as_admin,
    )

    assert response.status_code == 200
    assert response.json()["last_error"] is None


def test_the_audit_entry_says_a_token_was_rotated_without_saying_what_to(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    created = register(db_client, console, application).json()

    db_client.patch(
        f"{TARGETS}/{created['id']}",
        json={"token": "a-brand-new-secret"},
        headers=console.as_admin,
    )

    async def read(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "provisioning_target.updated")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    event = run_db(read)
    assert event is not None
    assert event.detail["token_rotated"] is True
    assert "a-brand-new-secret" not in str(event.detail)


def test_changing_the_address_re_checks_it(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Otherwise the rules only apply on the way in, and moving a target somewhere
    refused would be a way around them."""
    created = register(db_client, console, application).json()

    response = db_client.patch(
        f"{TARGETS}/{created['id']}",
        json={"base_url": "http://169.254.169.254/scim/v2"},
        headers=console.as_admin,
    )

    assert response.status_code == 400
    assert "link-local" in response.json()["detail"]


def test_disabling_a_target(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    created = register(db_client, console, application).json()

    response = db_client.patch(
        f"{TARGETS}/{created['id']}", json={"enabled": False}, headers=console.as_admin
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False


def test_an_empty_update_is_refused(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    created = register(db_client, console, application).json()

    response = db_client.patch(f"{TARGETS}/{created['id']}", json={}, headers=console.as_admin)

    assert response.status_code == 400


# ---------------------------------------------------------------- deleting


def test_deleting_a_target_says_what_it_did_not_do(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """It does not deactivate anybody, and the audit entry has to say so — otherwise
    somebody reads "target deleted" as "access removed"."""
    created = register(db_client, console, application).json()

    response = db_client.delete(f"{TARGETS}/{created['id']}", headers=console.as_admin)
    assert response.status_code == 204

    async def read(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "provisioning_target.deleted")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    event = run_db(read)
    assert event is not None
    assert "does not deactivate anybody" in event.detail["note"]
    assert event.detail["accounts_left_active_downstream"] == 0


def test_deleting_something_that_is_not_there(db_client: TestClient, console: ConsoleUsers) -> None:
    response = db_client.delete(f"{TARGETS}/{uuid.uuid4()}", headers=console.as_admin)

    assert response.status_code == 404


# -------------------------------------------------------- probing and syncing


def test_probing_an_unreachable_target_reports_rather_than_errors(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Nothing is listening on port 1, so this is the "cannot reach it" answer — which
    is information, not a server error on our side."""
    created = register(
        db_client, console, application, base_url="http://127.0.0.1:1/scim/v2"
    ).json()

    response = db_client.post(f"{TARGETS}/{created['id']}/probe", headers=console.as_admin)

    assert response.status_code == 200
    assert response.json()["reachable"] is False
    assert "could not reach" in response.json()["detail"]


def test_syncing_a_target_nobody_is_entitled_to_does_nothing(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """Nobody has access to the application, so there is nothing to push — and no
    requests are made, so an unreachable address does not matter."""
    created = register(
        db_client, console, application, base_url="http://127.0.0.1:1/scim/v2"
    ).json()

    response = db_client.post(f"{TARGETS}/{created['id']}/sync", headers=console.as_admin)

    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 0
    assert body["failed"] == 0
    assert body["ok"] is True
    # Every audit entry from the run shares this, which is what makes a cascade
    # readable as one story.
    assert body["correlation_id"]


def test_a_disabled_target_reports_why_it_did_nothing(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    created = register(db_client, console, application).json()
    db_client.patch(f"{TARGETS}/{created['id']}", json={"enabled": False}, headers=console.as_admin)

    response = db_client.post(f"{TARGETS}/{created['id']}/sync", headers=console.as_admin)

    assert response.status_code == 200
    assert response.json()["stopped_early"] == "the target is switched off"


def test_listing_accounts_for_a_target_with_none(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    created = register(db_client, console, application).json()

    response = db_client.get(f"{TARGETS}/{created['id']}/accounts", headers=console.as_admin)

    assert response.status_code == 200
    assert response.json() == []


def test_a_field_we_do_not_know_is_refused_rather_than_ignored(
    db_client: TestClient, console: ConsoleUsers, application: uuid.UUID
) -> None:
    """push_groups was a real version of this mistake.

    It sat on the model, was settable, and was read by nothing — so switching it on
    returned a 200 and did precisely nothing. A missing feature is visible. A switch
    that takes a value and discards it is not, and somebody walks away believing group
    membership is being pushed downstream.
    """
    refused = db_client.post(
        TARGETS,
        json={
            "application_id": str(application),
            "base_url": "https://downstream.test/scim/v2",
            "token": "a-downstream-token",
            "push_groups": True,
        },
        headers=console.as_admin,
    )

    assert refused.status_code == 422, refused.text[:300]
    # Named, not just refused. "unexpected field" without saying which one sends
    # somebody diffing payloads by hand.
    assert "push_groups" in refused.text
