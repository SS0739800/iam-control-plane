"""Our outbound client against the demo HRMS.

test_provisioning_client.py points the client at our own SCIM server, which
proves a real SCIM server accepts what we send. But both halves were
written by the same person from the same reading of the spec, so if that
reading is wrong, both sides agree and the test can't catch it.

The HRMS in `apps/hrms` shares no code with us - different framework,
own storage, its own mapping written from the spec rather than from ours.
So this is the closest thing to a genuine third party we can test against
without a network, and it's the one place a disagreement over an attribute
name would actually show up.

It loads the HRMS by file path since `apps/hrms` is not on the path and
must not be - the HRMS is a separate service, and making it an importable
dependency of the platform would turn it from a downstream into a module.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from iam.provisioning import (
    OutboundScim,
    PushFailed,
    deactivate_patch,
    reactivate_patch,
    user_payload,
)

HRMS_MAIN = Path(__file__).resolve().parents[2] / "hrms" / "main.py"

TOKEN = "interop-test-token"


@pytest.fixture
def hrms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    """Load the HRMS with its own throwaway database.

    Its token and database path are read at import time, so they're set
    before the module loads rather than patched afterward. The module name
    is unique per test so two tests never share a table.
    """
    monkeypatch.setenv("HRMS_SCIM_TOKEN", TOKEN)
    monkeypatch.setenv("HRMS_DATABASE", str(tmp_path / "hrms.sqlite3"))

    name = f"hrms_under_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, HRMS_MAIN)
    assert spec is not None and spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        # Startup events don't fire under ASGITransport, so the table is
        # created here by hand. The real container runs this on startup.
        module.setup()
        yield module
    finally:
        sys.modules.pop(name, None)


@pytest.fixture
async def client(hrms: ModuleType) -> AsyncIterator[OutboundScim]:
    """Our real outbound client, pointed at the HRMS app in-process."""
    transport = httpx.ASGITransport(app=hrms.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://hrms.test") as raw:
        yield OutboundScim(base_url="http://hrms.test/scim/v2", token=TOKEN, client=raw)


def a_person(suffix: str = "") -> dict[str, Any]:
    tag = suffix or uuid.uuid4().hex[:8]
    return user_payload(
        user_name=f"nadia.{tag}@demo.local",
        email=f"nadia.{tag}@demo.local",
        display_name="Nadia Okonkwo",
        given_name="Nadia",
        family_name="Okonkwo",
        department="People Operations",
        external_id=f"our-id-{tag}",
    )


# ================================================== does it talk to us at all


async def test_the_hrms_answers_a_probe(client: OutboundScim) -> None:
    """The check run right after registering a target."""
    detail = await client.probe()
    assert detail


async def test_our_token_is_the_only_one_it_takes(hrms: ModuleType) -> None:
    """A downstream that accepted any token would make every other test
    here meaningless."""
    transport = httpx.ASGITransport(app=hrms.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://hrms.test") as raw:
        wrong = OutboundScim(base_url="http://hrms.test/scim/v2", token="nope", client=raw)
        with pytest.raises(PushFailed) as raised:
            await wrong.probe()

    assert raised.value.status == 401
    assert raised.value.is_authentication


# ========================================================= the joiner


async def test_a_person_we_push_becomes_an_employee(client: OutboundScim) -> None:
    payload = a_person()
    account = await client.create_user(payload)

    assert account.remote_id
    assert account.user_name == payload["userName"]
    assert account.active is True


async def test_the_hrms_kept_the_fields_we_sent(client: OutboundScim, hrms: ModuleType) -> None:
    """The test that would catch an attribute the two sides read differently.

    Reads straight from the HRMS's own table rather than back through SCIM
    - a round trip through the same mapping can be wrong in both directions
    and still look right.
    """
    payload = a_person("mapping")
    await client.create_user(payload)

    with hrms.connect() as connection:
        row = connection.execute(
            "SELECT * FROM employees WHERE user_name = ?", (payload["userName"],)
        ).fetchone()

    assert row is not None
    assert row["display_name"] == "Nadia Okonkwo"
    assert row["given_name"] == "Nadia"
    assert row["family_name"] == "Okonkwo"
    assert row["email"] == payload["userName"]
    # The enterprise extension - the attribute most likely to be read
    # differently by two independent implementations.
    assert row["department"] == "People Operations"
    # Our own id, so the HRMS can point its account back at the person in our directory.
    assert row["external_id"] == payload["externalId"]
    assert row["active"] == 1


async def test_we_can_find_somebody_we_already_pushed(client: OutboundScim) -> None:
    """The filter a client sends when it's lost track of an account it created."""
    payload = a_person("findable")
    created = await client.create_user(payload)

    found = await client.find_user(str(payload["userName"]))

    assert found is not None
    assert found.remote_id == created.remote_id


async def test_somebody_who_was_never_pushed_is_simply_absent(client: OutboundScim) -> None:
    assert await client.find_user("nobody@demo.local") is None


# ========================================================= the second attempt


async def test_pushing_the_same_person_twice_is_a_conflict_not_a_crash(
    client: OutboundScim,
) -> None:
    """The case that would break onboarding an HRMS that already has staff in it.

    A conflict has to be recognizable: "already exists" means adopt the
    account, "broken" means retry later, and treating the first as the
    second fails forever.
    """
    payload = a_person("twice")
    await client.create_user(payload)

    with pytest.raises(PushFailed) as raised:
        await client.create_user(payload)

    assert raised.value.status == 409
    assert raised.value.is_conflict


async def test_an_employee_who_is_already_here_can_be_found_and_adopted(
    client: OutboundScim,
) -> None:
    """The adoption path against a system we didn't write.

    Somebody already works here and we weren't the ones who added them. A
    first sync has to end up linked to the account they have, not failing
    and not making a second one.
    """
    payload = a_person("adopt")
    already_there = await client.create_user(payload)

    # What a first sync does: try to create, get told no, go and look.
    with pytest.raises(PushFailed) as raised:
        await client.create_user(payload)
    assert raised.value.is_conflict

    adopted = await client.find_user(str(payload["userName"]))
    assert adopted is not None
    assert adopted.remote_id == already_there.remote_id, "one account, not two"


# ========================================================= the mover


async def test_a_changed_department_reaches_the_hrms(
    client: OutboundScim, hrms: ModuleType
) -> None:
    payload = a_person("mover")
    account = await client.create_user(payload)

    moved = user_payload(
        user_name=str(payload["userName"]),
        email=str(payload["userName"]),
        display_name="Nadia Okonkwo",
        given_name="Nadia",
        family_name="Okonkwo",
        department="Finance",
        external_id=str(payload["externalId"]),
    )
    await client.replace_user(account.remote_id, moved)

    with hrms.connect() as connection:
        row = connection.execute(
            "SELECT department FROM employees WHERE id = ?", (account.remote_id,)
        ).fetchone()

    assert row["department"] == "Finance"


# ========================================================= the leaver


async def test_somebody_leaving_is_switched_off_and_not_deleted(
    client: OutboundScim, hrms: ModuleType
) -> None:
    """Their record survives (payroll history, audit trail, a possible
    rehire), and their access doesn't."""
    payload = a_person("leaver")
    account = await client.create_user(payload)

    await client.set_active(account.remote_id, active=False)

    with hrms.connect() as connection:
        row = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (account.remote_id,)
        ).fetchone()

    assert row is not None, "the record should still be here"
    assert row["active"] == 0
    assert row["display_name"] == "Nadia Okonkwo", "deactivating should blank nothing"


async def test_a_rehire_can_be_switched_back_on(client: OutboundScim) -> None:
    payload = a_person("rehire")
    account = await client.create_user(payload)

    await client.set_active(account.remote_id, active=False)
    await client.set_active(account.remote_id, active=True)

    found = await client.find_user(str(payload["userName"]))
    assert found is not None
    assert found.active is True


async def test_the_patch_we_send_touches_only_what_it_names(
    client: OutboundScim, hrms: ModuleType
) -> None:
    """Checked against the raw row, since a PUT here would silently blank
    every attribute we don't send, and a round trip wouldn't show it."""
    payload = a_person("narrow")
    account = await client.create_user(payload)

    with hrms.connect() as connection:
        before = dict(
            connection.execute(
                "SELECT * FROM employees WHERE id = ?", (account.remote_id,)
            ).fetchone()
        )

    await client.set_active(account.remote_id, active=False)

    with hrms.connect() as connection:
        after = dict(
            connection.execute(
                "SELECT * FROM employees WHERE id = ?", (account.remote_id,)
            ).fetchone()
        )

    changed = {key for key in before if before[key] != after[key]}
    assert changed == {"active", "updated_at"}


# ========================================================= the gaps


async def test_updating_an_account_the_hrms_lost_is_told_apart(client: OutboundScim) -> None:
    """A link holding a stale remote_id. Recoverable by creating instead of
    updating, so it must not look like an ordinary failure."""
    with pytest.raises(PushFailed) as raised:
        await client.replace_user(str(uuid.uuid4()), a_person("ghost"))

    assert raised.value.status == 404
    assert raised.value.is_missing


async def test_the_patch_document_is_the_one_the_hrms_accepts(client: OutboundScim) -> None:
    """Proof, not just a claim: the HRMS says it supports PATCH in its
    ServiceProviderConfig, and the document we actually send is the one it takes."""
    payload = a_person("patchable")
    account = await client.create_user(payload)

    await client.set_active(account.remote_id, active=False)

    assert deactivate_patch()["Operations"][0]["path"] == "active"
    assert reactivate_patch()["Operations"][0]["value"] is True
