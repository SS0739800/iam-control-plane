"""Tests for who can do what, and for how we work out who's calling.

The production test is the one that matters. Login is real now, but the
development stand-in is still sitting behind it for requests that arrive without
a session cookie, and this test is the only thing making sure that header can't
work in production. Without it, one careless refactor turns it into a way past
the front door.
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
from iam.security.actor import NOT_SIGNED_IN
from tests.support import signing_keypair

UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent"

WRITE_PERMISSIONS = frozenset(
    {
        Permission.USERS_WRITE,
        Permission.GROUPS_WRITE,
        Permission.APPS_WRITE,
        Permission.IDP_WRITE,
    }
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


def test_only_an_admin_may_register_an_identity_provider() -> None:
    """The most consequential write there is. Whoever can change which certificate
    a login is checked against can decide who gets to be anybody, so helpdesk and
    auditor can look and nothing more."""
    for role in (PlatformRole.HELPDESK, PlatformRole.AUDITOR):
        assert Permission.IDP_READ in permissions_for(role)
        assert Permission.IDP_WRITE not in permissions_for(role)

    assert Permission.IDP_WRITE in permissions_for(PlatformRole.ADMIN)
    assert Permission.IDP_READ not in permissions_for(PlatformRole.EMPLOYEE)


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


# ------------------------------------------------ the development stand-in


def test_production_ignores_the_development_header() -> None:
    """The dev header must do nothing at all in production.

    Not "switched off by a setting". Production returns before the branch that
    reads it, and DEV_ACTOR_USER_NAME being set changes nothing. If this test ever
    fails, that header has become a way in.

    A 401 here also proves the header was ignored rather than tried: the database
    is unreachable, so a code path that looked the user up would fail differently.
    """
    # A production app refuses to start without a signing keypair, so this supplies
    # one. Nothing here is about signing — it just has to get past the guard.
    keypair = signing_keypair()
    settings = Settings(
        app_env="production",
        session_secret="a-real-secret-value-for-this-test",
        database_url=UNREACHABLE_DATABASE_URL,
        dev_actor_user_name="admin@demo.local",
        saml_idp_private_key=keypair.private_key_pem,
        saml_idp_certificate=keypair.certificate_pem,
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/api/dashboard", headers={"X-Dev-Actor": "admin@demo.local"})

    assert response.status_code == 401
    assert response.json()["detail"] == NOT_SIGNED_IN


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
