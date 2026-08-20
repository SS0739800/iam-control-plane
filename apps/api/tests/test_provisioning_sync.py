"""Tests for the sync: what gets pushed, and when.

The client's own tests point at our real SCIM server, because interoperability is
worth proving against a real implementation. These point at the stub in
tests/scim_stub.py instead, for the reason that file explains: this is asking whether
the sync makes the right decisions, and pointing it at our own app makes it contend
with itself for the audit log's advisory lock.

Every request still goes through the real ``OutboundScim``, so the headers, filter
escaping and status handling are real. Only the far end is pretend — and being pretend
is what lets a test say "answer 401" or "fail for this one person", which our own
server cannot be asked to do.

Four claims carry the phase: a joiner gets an account, a leaver is deactivated rather
than deleted, a second pass over an unchanged directory does nothing, and one bad
record does not stop the others.

Needs Postgres for our own state, and skips without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import iam.provisioning.sync as sync_module
from iam.db import build_engine, build_sessionmaker
from iam.models.application import AppAssignment, Application
from iam.models.audit import AuditEvent
from iam.models.enums import AppProtocol, AppStatus, IdentitySource, LinkState, PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from iam.models.user import User
from iam.provisioning.client import OutboundScim
from iam.provisioning.sync import MAX_ATTEMPTS, entitled_people, push_one, reconcile
from iam.secrets import encrypt
from tests import scim_stub
from tests.support import build_settings, database_url

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig() -> AsyncIterator[dict[str, Any]]:
    """A target, a stub downstream, and one session factory for our own state."""
    settings = build_settings(database_url())
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)

    suffix = uuid.uuid4().hex[:12]
    downstream = scim_stub.Downstream(token=f"token-{suffix}")
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=scim_stub.build(downstream)),
        base_url="http://downstream.test",
    )

    async with sessionmaker() as session:
        application = Application(
            name=f"Downstream {suffix}",
            slug=f"downstream-{suffix}",
            protocol=AppProtocol.SCIM2,
            status=AppStatus.ACTIVE,
        )
        session.add(application)
        await session.flush()

        target = ProvisioningTarget(
            application_id=application.id,
            base_url="http://downstream.test/scim/v2",
            token_encrypted=encrypt(downstream.token, settings),
            enabled=True,
        )
        session.add(target)
        await session.commit()
        app_id, target_id = application.id, target.id

    # The sync builds its own client, so the transport is patched in rather than
    # threaded through the whole signature purely for tests.
    original = sync_module._client_for
    sync_module._client_for = lambda row, active: OutboundScim(  # type: ignore[assignment]
        base_url=row.scim_root, token=downstream.token, client=http
    )

    # The clock the pushes are stamped with, read from the database rather than typed
    # in. users.updated_at comes from the database via func.now(); the timestamp it
    # gets compared against is whatever the caller hands reconcile(). A hard-coded
    # literal makes the staleness check ask "is this person's real modification time
    # later than a date somebody typed", which is true for everybody once the wall
    # clock passes it.
    #
    # This was a literal — noon on the day it was written — so the suite went red at
    # noon that day, and the failure reads like a broken staleness check rather than a
    # broken fixture. Taking the clock from the same place updated_at comes from says
    # what these tests actually mean: we pushed them after they last changed.
    async with sessionmaker() as session:
        stamped = await session.scalar(select(func.now()))
        assert isinstance(stamped, dt.datetime)
        now = stamped + dt.timedelta(seconds=1)

    yield {
        "app_id": app_id,
        "target_id": target_id,
        "suffix": suffix,
        "sessionmaker": sessionmaker,
        "settings": settings,
        "downstream": downstream,
        "now": now,
    }

    sync_module._client_for = original
    await http.aclose()

    async with sessionmaker() as session:
        await session.execute(
            delete(ProvisioningLink).where(ProvisioningLink.target_id == target_id)
        )
        await session.execute(delete(ProvisioningTarget).where(ProvisioningTarget.id == target_id))
        await session.execute(delete(AppAssignment).where(AppAssignment.application_id == app_id))
        await session.execute(delete(Application).where(Application.id == app_id))
        await session.execute(
            delete(GroupMember).where(
                GroupMember.group_id.in_(select(Group.id).where(Group.name.like(f"%{suffix}%")))
            )
        )
        await session.execute(delete(Group).where(Group.name.like(f"%{suffix}%")))
        await session.execute(delete(User).where(User.user_name.like(f"%{suffix}%")))
        await session.commit()

    await engine.dispose()


# ------------------------------------------------------------------- helpers


def factory(rig: dict[str, Any]) -> async_sessionmaker[AsyncSession]:
    maker: async_sessionmaker[AsyncSession] = rig["sessionmaker"]
    return maker


def user_name_for(rig: dict[str, Any], label: str) -> str:
    return f"{label}.{rig['suffix']}@demo.local"


async def add_person(rig: dict[str, Any], label: str, *, active: bool = True) -> uuid.UUID:
    """Somebody with access to the target's application."""
    async with factory(rig)() as session:
        person = User(
            user_name=user_name_for(rig, label),
            email=user_name_for(rig, label),
            display_name=f"{label.title()} {rig['suffix']}",
            active=active,
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.MANUAL,
            department="Engineering",
        )
        session.add(person)
        await session.flush()
        session.add(AppAssignment(application_id=rig["app_id"], user_id=person.id))
        await session.commit()
        return person.id


async def revoke_access(rig: dict[str, Any], person_id: uuid.UUID) -> None:
    async with factory(rig)() as session:
        await session.execute(
            delete(AppAssignment).where(
                AppAssignment.application_id == rig["app_id"],
                AppAssignment.user_id == person_id,
            )
        )
        await session.commit()


async def sync(rig: dict[str, Any], *, force: bool = False) -> Any:
    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        assert target is not None
        await session.refresh(target, ["application"])
        return await reconcile(session, target, rig["settings"], now=rig["now"], force=force)


async def links(rig: dict[str, Any]) -> list[ProvisioningLink]:
    async with factory(rig)() as session:
        rows = await session.scalars(
            select(ProvisioningLink).where(ProvisioningLink.target_id == rig["target_id"])
        )
        return list(rows.all())


# ------------------------------------------------------------ who is entitled


async def test_entitlement_comes_from_the_application(rig: dict[str, Any]) -> None:
    """No second notion of who belongs where. These are the same rows P5 reads before
    it will sign a login."""
    await add_person(rig, "wanted")

    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        assert target is not None
        names = [person.user_name for person in await entitled_people(session, target)]

    assert names == [user_name_for(rig, "wanted")]


async def test_group_access_counts_too(rig: dict[str, Any]) -> None:
    """Access through a group is how it should usually be given, so the sync has to
    see it."""
    async with factory(rig)() as session:
        group = Group(name=f"team-{rig['suffix']}", source=IdentitySource.MANUAL)
        session.add(group)
        await session.flush()

        person = User(
            user_name=user_name_for(rig, "viagroup"),
            email=user_name_for(rig, "viagroup"),
            display_name="Via Group",
            active=True,
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.MANUAL,
        )
        session.add(person)
        await session.flush()
        session.add(GroupMember(group_id=group.id, user_id=person.id))
        session.add(AppAssignment(application_id=rig["app_id"], group_id=group.id))
        await session.commit()

    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        assert target is not None
        names = [person.user_name for person in await entitled_people(session, target)]

    assert names == [user_name_for(rig, "viagroup")]


async def test_a_deactivated_person_is_not_entitled(rig: dict[str, Any]) -> None:
    """They keep their link, and a link with nobody entitled behind it is what
    triggers deprovisioning."""
    await add_person(rig, "gone", active=False)

    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        assert target is not None
        assert await entitled_people(session, target) == []


# ---------------------------------------------------------------- the joiner


async def test_granting_access_creates_an_account(rig: dict[str, Any]) -> None:
    await add_person(rig, "joiner")

    outcome = await sync(rig)

    assert outcome.created == 1
    assert outcome.failed == 0
    assert outcome.ok

    stored = await links(rig)
    assert len(stored) == 1
    assert stored[0].state is LinkState.ACTIVE
    # The id the downstream assigned, which is what makes updating and deactivating
    # possible at all.
    assert stored[0].remote_id is not None

    assert rig["downstream"].is_active(user_name_for(rig, "joiner")) is True


async def test_the_account_carries_our_own_id(rig: dict[str, Any]) -> None:
    """externalId is our id, not their email — so a downstream can still match the
    account after somebody changes their name."""
    person_id = await add_person(rig, "external")

    await sync(rig)

    account = rig["downstream"].account_for(user_name_for(rig, "external"))
    assert account is not None
    assert account["externalId"] == str(person_id)


async def test_a_second_pass_over_an_unchanged_directory_does_nothing(
    rig: dict[str, Any],
) -> None:
    """Without this every sync re-pushes everybody, which is a thousand requests to
    reach the answer it already had."""
    await add_person(rig, "steady")

    first = await sync(rig)
    before = len(rig["downstream"].requests)
    second = await sync(rig)

    assert first.created == 1
    assert second.created == 0
    assert second.unchanged == 1
    assert not second.changed
    # And it really did not talk to the downstream about that person again.
    assert len(rig["downstream"].requests) == before


async def test_forcing_pushes_even_when_nothing_changed(rig: dict[str, Any]) -> None:
    """What a manual "sync now" means: do not trust the staleness check."""
    await add_person(rig, "forced")
    await sync(rig)

    forced = await sync(rig, force=True)

    assert forced.updated == 1
    assert forced.unchanged == 0


async def test_an_account_that_already_exists_is_adopted(rig: dict[str, Any]) -> None:
    """What onboarding a downstream that already has people looks like.

    Without this every one of them fails forever on a 409, which is the normal case
    for anything other than an empty system.
    """
    await add_person(rig, "existing")
    # Somebody is already there with the same userName, and we do not know its id.
    rig["downstream"].accounts["pre-existing-id"] = {
        "id": "pre-existing-id",
        "userName": user_name_for(rig, "existing"),
        "displayName": "Created By Somebody Else",
        "active": True,
    }

    outcome = await sync(rig)

    assert outcome.adopted == 1
    assert outcome.created == 0
    assert outcome.failed == 0

    stored = await links(rig)
    # Linked to the account that was already there rather than a second one.
    assert stored[0].remote_id == "pre-existing-id"
    assert len(rig["downstream"].accounts) == 1


async def test_an_ambiguous_search_is_refused_rather_than_guessed(
    rig: dict[str, Any],
) -> None:
    """Linking to an account at random is a mistake nobody can see afterwards."""
    await add_person(rig, "ambiguous")
    rig["downstream"].accounts["one"] = {
        "id": "one",
        "userName": user_name_for(rig, "ambiguous"),
        "active": True,
    }
    rig["downstream"].duplicate_for.add(user_name_for(rig, "ambiguous"))

    outcome = await sync(rig)

    assert outcome.failed == 1
    assert outcome.adopted == 0
    stored = await links(rig)
    assert stored[0].state is LinkState.FAILED
    assert "Refusing to guess" in (stored[0].last_error or "")


# ---------------------------------------------------------------- the leaver


async def test_losing_access_deactivates_the_account(rig: dict[str, Any]) -> None:
    """The operation the whole phase exists for."""
    person_id = await add_person(rig, "leaver")
    await sync(rig)

    await revoke_access(rig, person_id)
    outcome = await sync(rig)

    assert outcome.deactivated == 1

    stored = await links(rig)
    assert stored[0].state is LinkState.DEPROVISIONED
    # Kept, so a rehire revives this account instead of creating a second one.
    assert stored[0].remote_id is not None

    # Switched off downstream, not deleted.
    assert rig["downstream"].is_active(user_name_for(rig, "leaver")) is False
    assert rig["downstream"].account_for(user_name_for(rig, "leaver")) is not None


async def test_deactivating_uses_patch_so_the_record_survives(
    rig: dict[str, Any],
) -> None:
    """A PUT would blank every attribute the downstream holds that we do not send."""
    person_id = await add_person(rig, "keeps")
    await sync(rig)
    await revoke_access(rig, person_id)
    await sync(rig)

    account = rig["downstream"].account_for(user_name_for(rig, "keeps"))
    assert account is not None
    assert account["active"] is False
    # Still there, because deactivation only touched `active`.
    assert account["displayName"].startswith("Keeps")
    assert "PATCH" in rig["downstream"].methods


async def test_a_rehire_revives_the_same_account(rig: dict[str, Any]) -> None:
    person_id = await add_person(rig, "rehire")
    await sync(rig)
    first_remote = (await links(rig))[0].remote_id

    await revoke_access(rig, person_id)
    await sync(rig)

    async with factory(rig)() as session:
        session.add(AppAssignment(application_id=rig["app_id"], user_id=person_id))
        await session.commit()

    outcome = await sync(rig)

    assert outcome.reactivated == 1
    assert outcome.created == 0
    stored = await links(rig)
    assert stored[0].state is LinkState.ACTIVE
    assert stored[0].remote_id == first_remote
    assert rig["downstream"].is_active(user_name_for(rig, "rehire")) is True


async def test_a_failed_deprovision_is_orphaned_not_just_failed(
    rig: dict[str, Any],
) -> None:
    """The distinction that matters: we were told to remove somebody's access and
    could not, so they still have it. That is what a review has to surface."""
    person_id = await add_person(rig, "orphan")
    await sync(rig)
    await revoke_access(rig, person_id)
    rig["downstream"].fail_for.add(user_name_for(rig, "orphan"))

    outcome = await sync(rig)

    assert outcome.failed == 1
    assert outcome.deactivated == 0
    stored = await links(rig)
    assert stored[0].state is LinkState.ORPHANED


# ------------------------------------------------------------ when it breaks


async def test_one_bad_record_does_not_stop_the_others(rig: dict[str, Any]) -> None:
    """Otherwise one unpushable person blocks everybody behind them."""
    await add_person(rig, "afine")
    await add_person(rig, "bbroken")
    await add_person(rig, "cfine")
    rig["downstream"].fail_for.add(user_name_for(rig, "bbroken"))

    outcome = await sync(rig)

    assert outcome.created == 2
    assert outcome.failed == 1
    assert not outcome.ok


async def test_a_bad_token_stops_the_run_rather_than_repeating(
    rig: dict[str, Any],
) -> None:
    """Grinding through a thousand people to collect a thousand identical 401s helps
    nobody and looks like a retry storm from the far end."""
    for index in range(3):
        await add_person(rig, f"blocked{index}")
    rig["downstream"].reject_token = True

    outcome = await sync(rig)

    assert outcome.stopped_early is not None
    assert "token" in outcome.stopped_early
    # One failure, not three.
    assert outcome.failed == 1
    assert outcome.created == 0


async def test_an_exhausted_link_is_left_alone_until_forced(
    rig: dict[str, Any],
) -> None:
    """A link failing five times is failing for a reason a retry will not fix, and
    retrying it every run buries the transient ones."""
    person_id = await add_person(rig, "stuck")
    async with factory(rig)() as session:
        session.add(
            ProvisioningLink(
                target_id=rig["target_id"],
                user_id=person_id,
                state=LinkState.FAILED,
                attempts=MAX_ATTEMPTS,
                last_error="something that will not fix itself",
            )
        )
        await session.commit()

    left_alone = await sync(rig)
    assert left_alone.skipped_exhausted == 1
    assert left_alone.created == 0

    forced = await sync(rig, force=True)
    assert forced.created == 1


async def test_a_disabled_target_pushes_nothing(rig: dict[str, Any]) -> None:
    """Turning a target off stops pushes without losing the links, so turning it back
    on does not recreate every account."""
    await add_person(rig, "paused")
    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        assert target is not None
        target.enabled = False
        await session.commit()

    outcome = await sync(rig)

    assert outcome.stopped_early is not None
    assert outcome.created == 0
    assert rig["downstream"].requests == []


# ------------------------------------------------------ one run, one story


async def test_every_event_in_a_run_shares_a_correlation_id(
    rig: dict[str, Any],
) -> None:
    """The reason that column has existed since P1. A sync that touches forty people
    is one event to a person and forty-odd rows in the log."""
    for index in range(3):
        await add_person(rig, f"crowd{index}")

    outcome = await sync(rig)

    async with factory(rig)() as session:
        rows = await session.scalars(
            select(AuditEvent.action).where(AuditEvent.correlation_id == outcome.correlation_id)
        )
        actions = list(rows.all())

    assert "provisioning.sync_started" in actions
    assert "provisioning.sync_finished" in actions
    assert actions.count("provisioning.account_created") == 3
    assert outcome.created == 3


async def test_a_failure_is_recorded_with_its_consequence(rig: dict[str, Any]) -> None:
    """An audit entry for a failed deprovision has to say what it means, because
    "push failed" does not convey that somebody still has access."""
    person_id = await add_person(rig, "consequence")
    await sync(rig)
    await revoke_access(rig, person_id)
    rig["downstream"].fail_for.add(user_name_for(rig, "consequence"))

    outcome = await sync(rig)

    async with factory(rig)() as session:
        row = await session.scalar(
            select(AuditEvent).where(
                AuditEvent.correlation_id == outcome.correlation_id,
                AuditEvent.action == "provisioning.deprovision_failed",
            )
        )

    assert row is not None
    assert "still have access" in row.detail["consequence"]


# ------------------------------------------------------- pushing one person


async def test_pushing_one_person_immediately(rig: dict[str, Any]) -> None:
    """The reaction on top of the baseline: somebody granted access gets an account
    now rather than at the next full pass."""
    person_id = await add_person(rig, "instant")

    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        person = await session.get(User, person_id)
        assert target is not None and person is not None
        await session.refresh(target, ["application"])
        assert await push_one(session, target, person, rig["settings"], now=rig["now"]) is True

    stored = await links(rig)
    assert len(stored) == 1
    assert stored[0].state is LinkState.ACTIVE
    assert rig["downstream"].is_active(user_name_for(rig, "instant")) is True


async def test_pushing_a_deactivated_person_switches_them_off(
    rig: dict[str, Any],
) -> None:
    """The immediate half of the leaver flow."""
    person_id = await add_person(rig, "instantleaver")
    await sync(rig)

    async with factory(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_id"])
        person = await session.get(User, person_id)
        assert target is not None and person is not None
        person.active = False
        await session.flush()
        await session.refresh(target, ["application"])
        assert await push_one(session, target, person, rig["settings"], now=rig["now"]) is True

    assert rig["downstream"].is_active(user_name_for(rig, "instantleaver")) is False
    stored = await links(rig)
    assert stored[0].state is LinkState.DEPROVISIONED
