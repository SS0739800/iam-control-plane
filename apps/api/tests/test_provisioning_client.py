"""Tests for the outbound SCIM client.

The payload and address tests need nothing. The rest point the client at our own SCIM
server, which is the best downstream available: it is a real SCIM 2.0 server, written
in P3 against the specification, with no knowledge that P6 exists.

That makes these interoperability tests rather than mock tests. A mock proves we send
what we decided to send; this proves a SCIM server accepts it. The two are not the
same, and only the second one would have caught a wrong content type or a filter that
does not parse.

The loop is not circular in the way it looks. The client creates accounts in our own
directory, which is odd but harmless — they are ordinary SCIM-created users, cleaned
up afterwards — and every request goes through the real server code, the real bearer
token check, and the real mapping.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.user import User
from iam.provisioning import (
    OutboundScim,
    PushFailed,
    check,
    deactivate_patch,
    user_payload,
)
from iam.provisioning.addresses import UnusableTarget
from tests.support import ScimCaller, with_db

# ============================================================ the payloads


def test_the_payload_carries_what_a_downstream_needs() -> None:
    document = user_payload(
        user_name="ada@demo.local",
        email="ada@demo.local",
        display_name="Ada Bergman",
        given_name="Ada",
        family_name="Bergman",
        external_id="our-id-123",
    )

    assert document["userName"] == "ada@demo.local"
    assert document["displayName"] == "Ada Bergman"
    assert document["active"] is True
    assert document["emails"][0] == {
        "value": "ada@demo.local",
        "type": "work",
        "primary": True,
    }
    assert document["name"] == {"givenName": "Ada", "familyName": "Bergman"}
    # Our own id, so a downstream can match its account back to us. The same field
    # our server side leans on when a provider writes to us.
    assert document["externalId"] == "our-id-123"


def test_a_department_brings_the_enterprise_extension_with_it() -> None:
    """Sending an extension attribute without declaring the schema is the mistake our
    own server side had to tolerate from real providers."""
    document = user_payload(
        user_name="ada@demo.local",
        email="ada@demo.local",
        display_name="Ada Bergman",
        department="Engineering",
    )

    enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    assert enterprise in document["schemas"]
    assert document[enterprise]["department"] == "Engineering"


def test_no_department_means_no_extension() -> None:
    """A downstream with a strict schema rejects an extension it was not expecting,
    and a rejected create is a person with no account."""
    document = user_payload(
        user_name="ada@demo.local", email="ada@demo.local", display_name="Ada Bergman"
    )

    assert document["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert not any(key.startswith("urn:ietf:params:scim:schemas:extension") for key in document)


def test_deactivating_is_a_patch_not_a_replace() -> None:
    """PUT would blank every attribute the downstream holds that we do not send. A
    leaver should lose their access, not their record."""
    patch = deactivate_patch()

    assert patch["Operations"] == [{"op": "replace", "path": "active", "value": False}]
    assert patch["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]


# ================================================= against our own SCIM server

pytestmark_integration = pytest.mark.integration


async def cleanup(user_name: str) -> None:
    async def work(session: AsyncSession) -> None:
        await session.execute(delete(User).where(User.user_name == user_name))

    await with_db(work)


async def stored(user_name: str) -> User | None:
    """Read the row the push created.

    Awaited rather than using run_db, because these tests are async and run_db calls
    asyncio.run. See tests/support.py.
    """

    async def work(session: AsyncSession) -> User | None:
        found: User | None = await session.scalar(select(User).where(User.user_name == user_name))
        return found

    return await with_db(work)


@pytest.fixture
def downstream(db_client: TestClient, caller: ScimCaller) -> Any:
    """The client, pointed at our own SCIM server through the test transport.

    httpx talks to the ASGI app directly rather than over a socket, so no server has
    to be listening — but every layer above the socket is real: routing, the bearer
    token check, the mapping, the database.
    """
    transport = httpx.ASGITransport(app=db_client.app)
    async_client = httpx.AsyncClient(transport=transport, base_url="http://testserver")

    yield OutboundScim(
        base_url="http://testserver/scim/v2",
        token=caller.token,
        client=async_client,
    )


@pytest.mark.integration
async def test_it_can_read_the_service_provider_config(downstream: OutboundScim) -> None:
    """The check somebody runs when registering a target: does it answer, and does the
    token work. Reads a document that describes nobody."""
    assert await downstream.probe()


@pytest.mark.integration
async def test_a_wrong_token_is_a_failure_not_a_success(
    db_client: TestClient,
) -> None:
    """The mistake this kind of client usually makes. A 401 is a perfectly successful
    HTTP request that provisioned nothing."""
    transport = httpx.ASGITransport(app=db_client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as raw:
        wrong = OutboundScim(
            base_url="http://testserver/scim/v2", token="not-a-real-token", client=raw
        )

        with pytest.raises(PushFailed) as raised:
            await wrong.probe()

    assert raised.value.status == 401
    # Told apart on purpose: every push to this target will fail the same way until
    # somebody re-enters the token, so a sync should stop rather than collect a
    # thousand identical failures.
    assert raised.value.is_authentication


@pytest.mark.integration
async def test_creating_an_account_downstream(downstream: OutboundScim) -> None:
    suffix = uuid.uuid4().hex[:12]
    user_name = f"pushed.{suffix}@downstream.local"

    try:
        account = await downstream.create_user(
            user_payload(
                user_name=user_name,
                email=user_name,
                display_name=f"Pushed {suffix}",
                external_id=f"our-{suffix}",
            )
        )

        assert account.remote_id
        assert account.user_name == user_name
        assert account.active is True

        # It really is there, as a real user in the directory.
        landed = await stored(user_name)
        assert landed is not None
        assert str(landed.id) == account.remote_id
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_the_account_it_creates_can_be_found_again(
    downstream: OutboundScim,
) -> None:
    """What adopting an existing downstream depends on: finding the account that is
    already there rather than creating a second copy of everybody."""
    suffix = uuid.uuid4().hex[:12]
    user_name = f"findable.{suffix}@downstream.local"

    try:
        created = await downstream.create_user(
            user_payload(user_name=user_name, email=user_name, display_name="Findable")
        )

        found = await downstream.find_user(user_name)

        assert found is not None
        assert found.remote_id == created.remote_id
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_looking_for_somebody_who_is_not_there(downstream: OutboundScim) -> None:
    assert await downstream.find_user("nobody.at.all@downstream.local") is None


@pytest.mark.integration
async def test_a_username_with_a_quote_cannot_break_the_filter(
    downstream: OutboundScim,
) -> None:
    """On somebody else's server an unescaped filter is their injection bug and our
    fault. Nothing should be found, and nothing should error."""
    assert await downstream.find_user('nobody" or userName pr "') is None


@pytest.mark.integration
async def test_deactivating_an_account(downstream: OutboundScim) -> None:
    """The operation the whole phase exists for."""
    suffix = uuid.uuid4().hex[:12]
    user_name = f"leaver.{suffix}@downstream.local"

    try:
        created = await downstream.create_user(
            user_payload(user_name=user_name, email=user_name, display_name="Leaver")
        )
        assert (await stored(user_name)) is not None

        await downstream.set_active(created.remote_id, active=False)

        # Deactivated, not deleted. The record survives, which is the whole point.
        after = await stored(user_name)
        assert after is not None
        assert after.active is False
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_deactivating_leaves_the_rest_of_the_record_alone(
    downstream: OutboundScim,
) -> None:
    """Why deactivation is a PATCH. A PUT would blank everything we did not send."""
    suffix = uuid.uuid4().hex[:12]
    user_name = f"keeps.{suffix}@downstream.local"

    try:
        created = await downstream.create_user(
            user_payload(
                user_name=user_name,
                email=user_name,
                display_name="Keeps Their Record",
                department="Engineering",
            )
        )

        await downstream.set_active(created.remote_id, active=False)

        after = await stored(user_name)
        assert after is not None
        assert after.active is False
        assert after.display_name == "Keeps Their Record"
        assert after.department == "Engineering"
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_a_rehire_reactivates_rather_than_duplicating(
    downstream: OutboundScim,
) -> None:
    suffix = uuid.uuid4().hex[:12]
    user_name = f"rehired.{suffix}@downstream.local"

    try:
        created = await downstream.create_user(
            user_payload(user_name=user_name, email=user_name, display_name="Rehired")
        )
        await downstream.set_active(created.remote_id, active=False)

        await downstream.set_active(created.remote_id, active=True)

        after = await stored(user_name)
        assert after is not None
        assert after.active is True
        assert str(after.id) == created.remote_id
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_updating_an_account(downstream: OutboundScim) -> None:
    suffix = uuid.uuid4().hex[:12]
    user_name = f"renamed.{suffix}@downstream.local"

    try:
        created = await downstream.create_user(
            user_payload(user_name=user_name, email=user_name, display_name="Before")
        )

        await downstream.replace_user(
            created.remote_id,
            user_payload(user_name=user_name, email=user_name, display_name="After"),
        )

        after = await stored(user_name)
        assert after is not None
        assert after.display_name == "After"
    finally:
        await cleanup(user_name)


@pytest.mark.integration
async def test_updating_an_account_that_is_not_there(downstream: OutboundScim) -> None:
    """Told apart from other failures because the recovery is specific: create rather
    than update, which is what a link with a stale remote_id needs."""
    with pytest.raises(PushFailed) as raised:
        await downstream.replace_user(
            str(uuid.uuid4()),
            user_payload(
                user_name="ghost@downstream.local",
                email="ghost@downstream.local",
                display_name="Ghost",
            ),
        )

    assert raised.value.is_missing


@pytest.mark.integration
async def test_a_target_that_is_not_there_at_all(db_client: TestClient) -> None:
    """No status, because there was no answer. A different problem from a rejected
    request, and usually a different person's to fix."""
    unreachable = OutboundScim(base_url="http://127.0.0.1:1/scim/v2", token="anything")

    with pytest.raises(PushFailed) as raised:
        await unreachable.probe()

    assert raised.value.status is None
    assert not raised.value.is_authentication


# ================================================= the addresses we will use


def test_a_compose_target_is_allowed_locally() -> None:
    decision = check("http://hrms:8000/scim/v2", is_production=False, allow_private=False)

    assert decision.host == "hrms"
    assert decision.concession == "plain HTTP, which is only allowed outside production"


def test_the_metadata_service_is_refused_with_everything_permitted() -> None:
    """The one rule with no escape hatch, because that address is where a cloud
    metadata service hands out credentials to anything that asks."""
    with pytest.raises(UnusableTarget, match="link-local"):
        check(
            "http://169.254.169.254/scim/v2",
            is_production=False,
            allow_private=True,
        )


def test_plain_http_is_refused_in_production() -> None:
    with pytest.raises(UnusableTarget, match="in the clear"):
        check("http://downstream.example/scim/v2", is_production=True, allow_private=True)


def test_a_private_address_needs_permission_in_production() -> None:
    with pytest.raises(UnusableTarget, match="private address"):
        check("https://10.0.0.5/scim/v2", is_production=True, allow_private=False)

    permitted = check("https://10.0.0.5/scim/v2", is_production=True, allow_private=True)
    assert permitted.concession is not None
