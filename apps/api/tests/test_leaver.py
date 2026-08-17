"""Someone left. Did anything actually stop?

The test at the bottom of this file is the one the whole project is for: sign in
over SAML, get given admin, be switched off by the provider over SCIM, and then
find that the session is dead, the admin is gone, the application access has gone,
and the audit log says all of it.

Everything else here checks one piece of that at a time, and checks the pieces
that should *not* move — group membership stays, the person's record stays, and
nothing comes back when they are reactivated.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access import Granter, cut_access, grant_role
from iam.models.access import RevokedGrantReason, RoleGrant
from iam.models.application import AppAssignment, Application
from iam.models.audit import AuditEvent
from iam.models.enums import AppProtocol, AppStatus, IdentitySource, PlatformRole
from iam.models.group import Group, GroupMember
from iam.models.saml import SamlSession
from iam.models.user import User
from iam.saml.sessions import create_session, lookup_session
from tests.saml_harness import (
    ConsoleUsers,
    Scenario,
    StubReader,
    sign_in,
)
from tests.support import run_db

pytestmark = pytest.mark.integration

NOW = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)

HR = Granter(user_id=None, label="HR system <hr@demo.local>")


async def make_leaver(
    db: AsyncSession,
    *,
    with_role: PlatformRole | None = None,
    with_app: bool = False,
    with_group: bool = False,
) -> User:
    """Somebody with some access, ready to lose it."""
    suffix = uuid.uuid4().hex[:12]
    user = User(
        user_name=f"leaver.{suffix}@demo.local",
        email=f"leaver.{suffix}@demo.local",
        display_name=f"Leaver {suffix}",
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.SCIM,
    )
    db.add(user)
    await db.flush()

    if with_role is not None:
        await grant_role(db, user, role=with_role, granter=HR, now=NOW)

    if with_app:
        app = Application(
            name=f"Salesforce {suffix}",
            slug=f"salesforce-{suffix}",
            protocol=AppProtocol.SAML2,
            status=AppStatus.ACTIVE,
        )
        db.add(app)
        await db.flush()
        db.add(AppAssignment(application_id=app.id, user_id=user.id, role="Sales Rep"))

    if with_group:
        group = Group(name=f"Sales {suffix}", source=IdentitySource.SCIM)
        db.add(group)
        await db.flush()
        db.add(GroupMember(group_id=group.id, user_id=user.id))

    await db.flush()
    return user


# ------------------------------------------------ what cutting access removes


async def test_every_session_ends_not_just_one(db_session: AsyncSession) -> None:
    """The failure this whole design exists to prevent: a flag flipped while they
    stay signed in for the next eight hours."""
    user = await make_leaver(db_session)
    tokens = []
    for index in range(3):
        _, token = await create_session(
            db_session,
            user_id=user.id,
            idp_slug="idp-leaver",
            name_id="persistent",
            name_id_format=None,
            session_index=f"index-{index}",
            issued_at=NOW,
        )
        tokens.append(token)

    removed = await cut_access(db_session, user, by=HR, now=NOW)

    assert removed.sessions_ended == 3
    for token in tokens:
        assert await lookup_session(db_session, token, now=NOW) is None


async def test_the_console_role_goes_and_says_why(db_session: AsyncSession) -> None:
    """An admin who left keeping admin is the thing this is all for."""
    user = await make_leaver(db_session, with_role=PlatformRole.ADMIN)
    user_id = user.id

    removed = await cut_access(db_session, user, by=HR, now=NOW)

    assert removed.role_revoked == PlatformRole.ADMIN
    assert user.platform_role == PlatformRole.EMPLOYEE

    grant = await db_session.scalar(select(RoleGrant).where(RoleGrant.user_id == user_id))
    assert grant is not None
    assert grant.revoked_reason == RevokedGrantReason.USER_DEACTIVATED


async def test_direct_application_access_goes(db_session: AsyncSession) -> None:
    user = await make_leaver(db_session, with_app=True)
    user_id = user.id

    removed = await cut_access(db_session, user, by=HR, now=NOW)

    assert len(removed.apps_removed) == 1
    # Named, with the role, because "lost Salesforce (Sales Rep)" is reviewable
    # and "app_assignments: 1" is not.
    assert "Sales Rep" in removed.apps_removed[0]

    left = await db_session.scalars(select(AppAssignment).where(AppAssignment.user_id == user_id))
    assert list(left) == []


async def test_group_membership_stays(db_session: AsyncSession) -> None:
    """Deliberate. An inactive person can't authenticate so it grants them nothing,
    and the provider owns these rows — deleting them means fighting the next sync
    forever. What they were in is recorded instead."""
    user = await make_leaver(db_session, with_group=True)
    user_id = user.id

    removed = await cut_access(db_session, user, by=HR, now=NOW)

    assert len(removed.groups_at_departure) == 1
    still_in = await db_session.scalars(select(GroupMember).where(GroupMember.user_id == user_id))
    assert len(list(still_in)) == 1


async def test_the_person_is_kept(db_session: AsyncSession) -> None:
    """Their history has to stay readable. Losing access is not losing the record
    of what they had."""
    user = await make_leaver(db_session, with_role=PlatformRole.HELPDESK)
    user_id = user.id

    await cut_access(db_session, user, by=HR, now=NOW)

    assert await db_session.get(User, user_id) is not None


async def test_cutting_access_twice_is_harmless(db_session: AsyncSession) -> None:
    """The provider re-sending active:false on every sync must not pile up entries."""
    user = await make_leaver(db_session, with_role=PlatformRole.ADMIN, with_app=True)

    first = await cut_access(db_session, user, by=HR, now=NOW)
    second = await cut_access(db_session, user, by=HR, now=NOW + dt.timedelta(hours=1))

    assert first.anything_happened is True
    assert second.anything_happened is False


async def test_cutting_access_leaves_other_people_alone(db_session: AsyncSession) -> None:
    leaver = await make_leaver(db_session, with_role=PlatformRole.HELPDESK, with_app=True)
    stayer = await make_leaver(db_session, with_role=PlatformRole.AUDITOR, with_app=True)
    stayer_id = stayer.id

    await cut_access(db_session, leaver, by=HR, now=NOW)

    assert stayer.platform_role == PlatformRole.AUDITOR
    theirs = await db_session.scalars(
        select(AppAssignment).where(AppAssignment.user_id == stayer_id)
    )
    assert len(list(theirs)) == 1


async def test_access_does_not_come_back_on_reactivation(db_session: AsyncSession) -> None:
    """A rehire silently regaining what they had two years ago is how people end up
    with access nobody would approve today."""
    user = await make_leaver(db_session, with_role=PlatformRole.ADMIN, with_app=True)
    await cut_access(db_session, user, by=HR, now=NOW)

    user.active = True
    await db_session.flush()

    assert user.platform_role == PlatformRole.EMPLOYEE
    left = await db_session.scalars(select(AppAssignment).where(AppAssignment.user_id == user.id))
    assert list(left) == []


# ------------------------------------------------------- the whole thing, live


def cleanup_leaver(user_name: str) -> None:
    async def work(session: AsyncSession) -> None:
        found = await session.scalar(select(User).where(User.user_name == user_name))
        if found is None:
            return
        await session.execute(delete(RoleGrant).where(RoleGrant.user_id == found.id))
        await session.execute(delete(SamlSession).where(SamlSession.user_id == found.id))
        await session.execute(delete(AppAssignment).where(AppAssignment.user_id == found.id))
        await session.execute(delete(User).where(User.id == found.id))

    run_db(work)


def test_signed_in_then_deactivated_upstream_loses_everything(
    saml_client: TestClient,
    scenario: Scenario,
    console: ConsoleUsers,
    saml_reader: StubReader,
) -> None:
    """The one that matters.

    Somebody signs in over SAML, an admin gives them a console role, and then the
    provider switches them off over SCIM. Every part of that is the real code path:
    a real assertion through /saml/acs, a real grant through the API, a real SCIM
    PATCH from a real provisioning token.

    Afterwards the session cookie must be dead, the role must be gone, and the
    audit log must say so. If this test passes, deprovisioning works.
    """
    # 1. They sign in for real, and hold a session cookie.
    sign_in(saml_client, scenario, saml_reader)
    cookie = saml_client.cookies["iam_session"]
    assert saml_client.get("/api/me", headers={"X-Dev-Actor": "nobody@demo.local"}).status_code == (
        200
    )

    user_id = console.id_of(scenario.user_name)

    # The client is holding Ada's cookie now, and a real session beats the
    # development header — that is the P2 rule and it is working. So the cookie has
    # to come off before this client can act as somebody else, or every admin call
    # below runs as Ada and gets a 403.
    saml_client.cookies.clear()

    # 2. An admin gives them a console role.
    granted = saml_client.post(
        f"/api/users/{user_id}/role-grants",
        json={"role": "helpdesk", "reason": "Joined the service desk"},
        headers=console.as_admin,
    )
    assert granted.status_code == 201, granted.text[:300]

    # 3. The provider switches them off. A real SCIM PATCH with a real token.
    token = issue_token(f"leaver-check-{scenario.suffix}")
    patched = saml_client.patch(
        f"/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patched.status_code == 200, patched.text[:300]
    assert patched.json()["active"] is False

    # 4. The cookie they were holding is now worthless.
    saml_client.cookies.set("iam_session", cookie)
    assert saml_client.get("/api/me", headers={"X-Dev-Actor": "nobody@demo.local"}).status_code in (
        401,
        403,
    )

    # 5. The role is gone.
    summary = saml_client.get(f"/api/users/{user_id}/access", headers=console.as_admin).json()
    assert summary["role"] == "employee"
    assert summary["active"] is False

    # 6. And the log says what happened, in one entry.
    async def find_entry(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action == "user.access_cut",
                AuditEvent.target_id == str(user_id),
            )
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    entry = run_db(find_entry)
    assert entry is not None, "deprovisioning happened but nothing was written down"
    assert entry.detail["role_revoked"] == "helpdesk"
    assert entry.detail["sessions_ended"] >= 1
    assert "SCIM client" in entry.actor_label


def issue_token(name: str) -> str:
    """A real provisioning token, the way the console issues them."""
    from iam.models.scim import ScimClient
    from iam.tokens import hash_token, new_token

    token = new_token()

    async def work(session: AsyncSession) -> None:
        session.add(
            ScimClient(
                name=name,
                description="Issued by the leaver test",
                token_hash=hash_token(token),
                enabled=True,
            )
        )

    run_db(work)
    return token
