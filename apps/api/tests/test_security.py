"""Tests for who can do what, and for the fact that login doesn't exist yet.

The production test is the one that matters. Until P2 there's no real login, just
the X-Dev-Actor header, and a test is the only thing making sure that header can't
work in production. Without it, one careless refactor turns it into a way past the
front door.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from iam.config import Settings
from iam.main import create_app
from iam.models.enums import PlatformRole
from iam.security import Actor, Permission, permissions_for, require

UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent"

WRITE_PERMISSIONS = frozenset(
    {Permission.USERS_WRITE, Permission.GROUPS_WRITE, Permission.APPS_WRITE}
)


def make_actor(role: PlatformRole) -> Actor:
    return Actor(
        user_id=uuid.uuid4(),
        user_name=f"{role.value}@demo.local",
        display_name=role.value.title(),
        role=role,
        permissions=permissions_for(role),
    )


# ---------------------------------------------------------- permission matrix


def test_admin_holds_every_permission() -> None:
    assert permissions_for(PlatformRole.ADMIN) == frozenset(Permission)


def test_employee_holds_nothing() -> None:
    """Regular staff use the HRMS. This console isn't for them."""
    assert permissions_for(PlatformRole.EMPLOYEE) == frozenset()


def test_auditor_can_read_everything_but_write_nothing() -> None:
    """The person checking access shouldn't also be able to hand it out."""
    auditor = permissions_for(PlatformRole.AUDITOR)

    assert Permission.USERS_READ in auditor
    assert Permission.GROUPS_READ in auditor
    assert Permission.APPS_READ in auditor
    assert Permission.AUDIT_READ in auditor
    assert Permission.AUDIT_VERIFY in auditor
    assert not (auditor & WRITE_PERMISSIONS)


def test_helpdesk_can_fix_users_but_not_reshape_access() -> None:
    """Editing a user affects one person. Editing a group affects everyone in it."""
    helpdesk = permissions_for(PlatformRole.HELPDESK)

    assert Permission.USERS_WRITE in helpdesk
    assert Permission.GROUPS_WRITE not in helpdesk
    assert Permission.APPS_WRITE not in helpdesk


def test_only_auditor_and_admin_may_verify_the_chain() -> None:
    allowed = {role for role in PlatformRole if Permission.AUDIT_VERIFY in permissions_for(role)}
    assert allowed == {PlatformRole.ADMIN, PlatformRole.AUDITOR}


# ------------------------------------------------------------------- the guard


async def test_guard_admits_an_actor_holding_the_permission() -> None:
    guard = require(Permission.USERS_READ)
    actor = make_actor(PlatformRole.ADMIN)

    assert await guard(actor) is actor


async def test_guard_rejects_an_actor_without_it() -> None:
    guard = require(Permission.USERS_WRITE)

    with pytest.raises(HTTPException) as raised:
        await guard(make_actor(PlatformRole.AUDITOR))

    assert raised.value.status_code == 403
    assert "users:write" in str(raised.value.detail)


async def test_guard_requires_every_listed_permission_not_merely_one() -> None:
    """Adding someone to a group touches users and groups. One isn't enough."""
    guard = require(Permission.USERS_WRITE, Permission.GROUPS_WRITE)

    with pytest.raises(HTTPException) as raised:
        await guard(make_actor(PlatformRole.HELPDESK))

    assert raised.value.status_code == 403
    assert "groups:write" in str(raised.value.detail)


def test_guard_with_no_permissions_is_a_programming_error() -> None:
    """A check that asks for nothing looks like protection but lets everyone in."""
    with pytest.raises(ValueError, match="at least one permission"):
        require()


# ------------------------------------------------- the P2 authentication gap


def test_production_refuses_to_authenticate_anyone() -> None:
    """The dev header must do nothing at all in production.

    Not "switched off by a setting". There's no code path in production that even
    looks at it. If this test ever fails, that header has become a way in.
    """
    settings = Settings(
        app_env="production",
        session_secret="a-real-secret-value-for-this-test",
        database_url=UNREACHABLE_DATABASE_URL,
        dev_actor_user_name="admin@demo.local",
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/api/dashboard", headers={"X-Dev-Actor": "admin@demo.local"})

    assert response.status_code == 401
    assert "P2" in response.json()["detail"]


def test_production_refuses_to_start_with_the_placeholder_secret() -> None:
    """Better to refuse to start than to sign cookies with a value from GitHub."""
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        create_app(Settings(app_env="production", database_url=UNREACHABLE_DATABASE_URL))


def test_development_requires_an_actor_to_be_named() -> None:
    """No header and no default configured means refuse, not guess."""
    settings = Settings(
        app_env="local",
        session_secret="local-secret",
        database_url=UNREACHABLE_DATABASE_URL,
        dev_actor_user_name=None,
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/api/dashboard")

    assert response.status_code == 401
    assert "X-Dev-Actor" in response.json()["detail"]
