"""The background sweep.

Provisioning used to happen only inside the request that asked for it, so a leaver
kept their downstream account until somebody opened the console and pressed a button.
That is not hypothetical here: Okta deactivated somebody at 8:51:40, the last sync had
run at 8:51:12, and the account stayed live until a person noticed.

What these check is mostly the failure behaviour, because the happy path is just
reconcile() — which has its own tests — called on a timer. What is new is everything
around it: that one broken target does not stop the others, that a paused target is
left alone, and that the loop survives a bad sweep rather than exiting and needing
somebody to notice.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from iam import worker
from iam.db import build_engine, build_sessionmaker
from iam.models.application import AppAssignment, Application
from iam.models.enums import AppProtocol, AppStatus, IdentitySource, PlatformRole
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from iam.models.user import User
from iam.provisioning import sync as sync_module
from iam.provisioning.client import OutboundScim
from iam.secrets import encrypt
from tests import scim_stub
from tests.support import build_settings, database_url

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig() -> AsyncIterator[dict[str, Any]]:
    """Two targets pointed at two stub downstreams, so "one failing" is testable."""
    settings = build_settings(database_url())
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)

    suffix = uuid.uuid4().hex[:12]
    downstreams = {}
    clients = {}
    target_ids = {}

    async with sessionmaker() as session:
        for name in ("alpha", "beta"):
            downstream = scim_stub.Downstream(token=f"token-{name}-{suffix}")
            downstreams[name] = downstream
            clients[name] = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=scim_stub.build(downstream)),
                base_url=f"http://{name}.test",
            )

            application = Application(
                name=f"{name.title()} {suffix}",
                slug=f"{name}-{suffix}",
                protocol=AppProtocol.SCIM2,
                status=AppStatus.ACTIVE,
            )
            session.add(application)
            await session.flush()

            target = ProvisioningTarget(
                application_id=application.id,
                base_url=f"http://{name}.test/scim/v2",
                token_encrypted=encrypt(downstream.token, settings),
                enabled=True,
            )
            session.add(target)
            await session.flush()
            target_ids[name] = target.id

            person = User(
                user_name=f"{name}.{suffix}@demo.local",
                email=f"{name}.{suffix}@demo.local",
                display_name=f"{name.title()} Person",
                active=True,
                platform_role=PlatformRole.EMPLOYEE,
                source=IdentitySource.MANUAL,
            )
            session.add(person)
            await session.flush()
            session.add(AppAssignment(application_id=application.id, user_id=person.id))
        await session.commit()

    original = sync_module._client_for

    def pick(row: ProvisioningTarget, active: bool) -> OutboundScim:
        name = "alpha" if "alpha" in row.base_url else "beta"
        return OutboundScim(
            base_url=row.scim_root, token=downstreams[name].token, client=clients[name]
        )

    sync_module._client_for = pick  # type: ignore[assignment]

    yield {
        "settings": settings,
        "sessionmaker": sessionmaker,
        "downstreams": downstreams,
        "target_ids": target_ids,
        "suffix": suffix,
    }

    sync_module._client_for = original
    for client in clients.values():
        await client.aclose()

    async with sessionmaker() as session:
        ids = list(target_ids.values())
        await session.execute(delete(ProvisioningLink).where(ProvisioningLink.target_id.in_(ids)))
        await session.execute(delete(ProvisioningTarget).where(ProvisioningTarget.id.in_(ids)))
        await session.execute(
            delete(AppAssignment).where(
                AppAssignment.application_id.in_(
                    select(Application.id).where(Application.slug.like(f"%{suffix}"))
                )
            )
        )
        await session.execute(delete(Application).where(Application.slug.like(f"%{suffix}")))
        await session.execute(delete(User).where(User.user_name.like(f"%{suffix}%")))
        await session.commit()
    await engine.dispose()


def maker(rig: dict[str, Any]) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = rig["sessionmaker"]
    return factory


async def sweep(rig: dict[str, Any]) -> dict[str, int]:
    return await worker.sweep_once(maker(rig), rig["settings"], now=dt.datetime.now(dt.UTC))


# ------------------------------------------------------------- the ordinary case


async def test_a_sweep_provisions_without_anybody_pressing_anything(
    rig: dict[str, Any],
) -> None:
    """The whole point. Nobody opened the console."""
    summary = await sweep(rig)

    assert summary["targets"] >= 2
    assert summary["failed"] == 0
    for name, downstream in rig["downstreams"].items():
        assert downstream.is_active(f"{name}.{rig['suffix']}@demo.local") is True


async def test_a_second_sweep_does_nothing(rig: dict[str, Any]) -> None:
    """A timer that re-pushed everybody every five minutes would be a thousand
    requests to reach the answer it already had."""
    await sweep(rig)
    before = {name: len(d.requests) for name, d in rig["downstreams"].items()}

    summary = await sweep(rig)

    assert summary["pushed"] == 0
    assert {name: len(d.requests) for name, d in rig["downstreams"].items()} == before


async def test_the_count_is_accounts_not_targets(rig: dict[str, Any]) -> None:
    """`changed` is a yes-or-no per target. Summing that would report "1 pushed"
    when forty people were provisioned, which is why `touched` exists."""
    summary = await sweep(rig)

    assert summary["pushed"] == 2  # one person in each of the two targets


# ------------------------------------------------------------------ the failures


async def test_one_broken_target_does_not_stop_the_other(rig: dict[str, Any]) -> None:
    """Somebody else's outage should not hold up everybody else's offboarding."""
    rig["downstreams"]["alpha"].reject_token = True

    summary = await sweep(rig)

    assert summary["failed"] >= 1
    # Beta still got its account, which is the assertion that matters.
    assert rig["downstreams"]["beta"].is_active(f"beta.{rig['suffix']}@demo.local") is True


async def test_a_paused_target_is_left_alone(rig: dict[str, Any]) -> None:
    async with maker(rig)() as session:
        target = await session.get(ProvisioningTarget, rig["target_ids"]["alpha"])
        assert target is not None
        target.enabled = False
        await session.commit()

    await sweep(rig)

    assert rig["downstreams"]["alpha"].account_for(f"alpha.{rig['suffix']}@demo.local") is None
    assert rig["downstreams"]["beta"].is_active(f"beta.{rig['suffix']}@demo.local") is True


async def test_a_leaver_is_switched_off_by_the_sweep(rig: dict[str, Any]) -> None:
    """The case that prompted the worker: a deactivation arriving after the last
    manual sync, with nobody around to press the button."""
    await sweep(rig)
    user_name = f"alpha.{rig['suffix']}@demo.local"
    assert rig["downstreams"]["alpha"].is_active(user_name) is True

    async with maker(rig)() as session:
        person = await session.scalar(select(User).where(User.user_name == user_name))
        assert person is not None
        person.active = False
        await session.commit()

    summary = await sweep(rig)

    assert summary["pushed"] >= 1
    assert rig["downstreams"]["alpha"].is_active(user_name) is False


# --------------------------------------------------------------------- the loop


async def test_the_loop_survives_a_failing_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that exits on the first bad minute is one somebody has to notice.

    The database being unreachable, a bad migration, a bug in reconcile — none of
    them should end the process, because the next sweep may well succeed and nothing
    is watching this thing.
    """
    calls = 0

    async def explode(*args: object, **kwargs: object) -> dict[str, int]:
        nonlocal calls
        calls += 1
        if calls >= 3:
            raise asyncio.CancelledError  # a stand-in for the process being stopped
        raise RuntimeError("the database is on fire")

    monkeypatch.setattr(worker, "sweep_once", explode)
    settings = build_settings().model_copy(update={"provisioning_sweep_seconds": 0})

    with pytest.raises(asyncio.CancelledError):
        await worker.run_forever(settings)

    assert calls == 3, "the loop gave up instead of trying again"
