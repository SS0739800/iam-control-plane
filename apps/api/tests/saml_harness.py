"""Shared setup for the SAML endpoint tests.

Not a test module. Holds the pieces both the assertion-consumer tests and the
sign-out tests need: unique names for one run, a stand-in for the reader, and
the seeding and querying helpers.

reader.py is the only module that needs xmlsec, so it's the only one that
can't be imported here or in CI. The endpoint takes it as a dependency, so
these tests hand it prepared facts and exercise everything after the
signature check for real: the checks, creating the person, the session, the
cookie, the redirect. The stub only replaces "read this XML and verify it",
never "decide whether this login is acceptable".
"""

from __future__ import annotations

import base64
import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.access import RoleGrant
from iam.models.enums import GrantSource, IdentitySource, PlatformRole
from iam.models.saml import IdentityProvider, SamlAssertionSeen, SamlRequestState, SamlSession
from iam.models.user import User
from iam.saml.checks import (
    SAML_SUCCESS,
    AssertionFacts,
    LogoutRequestFacts,
    LogoutResponseFacts,
)
from iam.saml.sp import REQUEST_TTL
from tests.support import run_db

BASE_URL = "http://localhost:8080"
OUR_ENTITY_ID = f"{BASE_URL}/saml/metadata"
OUR_ACS_URL = f"{BASE_URL}/saml/acs"

STUB_CERT = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"

# The endpoint hands this straight to the stub reader, which ignores it and
# returns whatever facts the test set up. Still real base64 of real-looking
# XML, since a failed login keeps the document for the inspector.
POSTED_RESPONSE = base64.b64encode(
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    b"<!-- the reader is stubbed; the facts come from the test -->"
    b"</samlp:Response>"
).decode("ascii")


class StubReader:
    """Stands in for reader.py, which can't be imported without xmlsec.

    Hands back facts the test prepared, or raises. It is *only* the reading and
    signature-verifying step; every check that follows is the real code.
    """

    def __init__(self) -> None:
        self.facts: AssertionFacts | None = None
        self.error: Exception | None = None
        self.certs_seen: list[str] = []

    def __call__(self, raw_response: str, signing_cert: str) -> AssertionFacts:
        self.certs_seen.append(signing_cert)
        if self.error is not None:
            raise self.error
        assert self.facts is not None, "the test did not set up any facts"
        return self.facts


class StubLogoutReader:
    """Stands in for reader.py's logout parsing, same seam as StubReader.

    Reads nothing. The test says what the message contained and whether its
    signature checked out; everything the endpoint decides from that is real.
    """

    def __init__(self) -> None:
        self.facts: LogoutRequestFacts | LogoutResponseFacts | None = None
        self.error: Exception | None = None
        self.certs_seen: list[str] = []

    def __call__(self, raw: str, signing_cert: str) -> Any:
        self.certs_seen.append(signing_cert)
        if self.error is not None:
            raise self.error
        assert self.facts is not None, "the test did not set up any facts"
        return self.facts


@dataclass(frozen=True, slots=True)
class Scenario:
    """One login's worth of test data, with names nothing else will collide with.

    The test database is shared and not reset between tests, so every run gets its
    own provider slug, request id and email address. Two tests that both wanted
    "authentik" would pass alone and fail together.
    """

    suffix: str

    @property
    def idp_slug(self) -> str:
        return f"idp-{self.suffix}"

    @property
    def idp_entity_id(self) -> str:
        return f"https://authentik-{self.suffix}.test"

    @property
    def relay_state(self) -> str:
        return f"relay-{self.suffix}"

    @property
    def request_id(self) -> str:
        return f"id-request-{self.suffix}"

    @property
    def assertion_id(self) -> str:
        return f"id-assertion-{self.suffix}"

    @property
    def user_name(self) -> str:
        return f"ada.{self.suffix}@demo.local"


@dataclass(frozen=True, slots=True)
class ConsoleUsers:
    """One console user per role, for testing who is allowed to do what.

    Created per test with unique names, since the test database is shared and
    isn't reset between tests. Nothing is seeded into it, so a test that wants
    to call an endpoint as an admin has to make one first.
    """

    suffix: str

    @property
    def admin(self) -> str:
        return f"admin.{self.suffix}@demo.local"

    @property
    def helpdesk(self) -> str:
        return f"helpdesk.{self.suffix}@demo.local"

    @property
    def auditor(self) -> str:
        return f"auditor.{self.suffix}@demo.local"

    @property
    def employee(self) -> str:
        return f"employee.{self.suffix}@demo.local"

    @property
    def slug(self) -> str:
        """A provider slug for tests that register one."""
        return f"authentik-{self.suffix}"

    @property
    def as_admin(self) -> dict[str, str]:
        """Headers that make a request come from the admin."""
        return {"X-Dev-Actor": self.admin}

    def as_user(self, user_name: str) -> dict[str, str]:
        return {"X-Dev-Actor": user_name}

    def id_of(self, user_name: str) -> uuid.UUID:
        """The database id for one of these people."""

        async def work(session: AsyncSession) -> uuid.UUID:
            found = await session.scalar(select(User).where(User.user_name == user_name))
            assert found is not None, f"{user_name} was not created"
            return found.id

        return run_db(work)

    def user_name_of(self, user_id: uuid.UUID) -> str:
        """The userName for an id, for tests that need to act as somebody they made."""

        async def work(session: AsyncSession) -> str:
            found = await session.get(User, user_id)
            assert found is not None, f"no user {user_id}"
            return found.user_name

        return run_db(work)

    @property
    def by_role(self) -> tuple[tuple[str, PlatformRole], ...]:
        return (
            (self.admin, PlatformRole.ADMIN),
            (self.helpdesk, PlatformRole.HELPDESK),
            (self.auditor, PlatformRole.AUDITOR),
            (self.employee, PlatformRole.EMPLOYEE),
        )

    @property
    def user_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.by_role)


def new_console_users() -> ConsoleUsers:
    return ConsoleUsers(suffix=uuid.uuid4().hex[:12])


def create_console_users(console: ConsoleUsers) -> None:
    """One user per role, with a real grant behind each one.

    Roles are decided by role_grants; the column on the user is just a cache
    of them. A fixture that set only the column would create people the drift
    check reports and the last-admin guard can't see, which would make "who
    may do what" tests exercise a state the app can't actually produce.
    """

    async def work(session: AsyncSession) -> None:
        for user_name, role in console.by_role:
            user = User(
                user_name=user_name,
                email=user_name,
                display_name=f"{role.value.title()} {console.suffix}",
                active=True,
                platform_role=role,
                source=IdentitySource.SEED,
            )
            session.add(user)
            await session.flush()

            # Employee is the absence of a grant, so it gets none.
            if role != PlatformRole.EMPLOYEE:
                session.add(
                    RoleGrant(
                        user_id=user.id,
                        role=role,
                        source=GrantSource.SEED,
                        reason="Created by the test fixture",
                        granted_by_label="the test fixture",
                    )
                )

    run_db(work)


def remove_console_users(console: ConsoleUsers) -> None:
    async def work(session: AsyncSession) -> None:
        await session.execute(
            delete(SamlRequestState).where(SamlRequestState.idp_slug == console.slug)
        )
        await session.execute(delete(IdentityProvider).where(IdentityProvider.slug == console.slug))
        # Grants first: they point at these users, and the cascade only fires
        # on a real DELETE of the parent row, which comes next.
        await session.execute(
            delete(RoleGrant).where(
                RoleGrant.user_id.in_(select(User.id).where(User.user_name.in_(console.user_names)))
            )
        )
        await session.execute(delete(User).where(User.user_name.in_(console.user_names)))

    run_db(work)


def new_scenario() -> Scenario:
    return Scenario(suffix=uuid.uuid4().hex[:12])


def clean_up(scenario: Scenario) -> None:
    """Remove everything one test made.

    Audit entries are left behind, since the table refuses DELETE.
    """

    async def work(session: AsyncSession) -> None:
        await session.execute(delete(SamlSession).where(SamlSession.idp_slug == scenario.idp_slug))
        await session.execute(delete(User).where(User.user_name == scenario.user_name))
        await session.execute(
            delete(SamlAssertionSeen).where(SamlAssertionSeen.issuer == scenario.idp_entity_id)
        )
        await session.execute(
            delete(SamlRequestState).where(SamlRequestState.idp_slug == scenario.idp_slug)
        )
        await session.execute(
            delete(IdentityProvider).where(IdentityProvider.slug == scenario.idp_slug)
        )

    run_db(work)


def seed_provider(scenario: Scenario, *, enabled: bool = True, slo_url: str | None = None) -> None:
    """Register a provider the way POST /api/identity-providers would.

    slo_url is off by default, since plenty of providers have no logout
    address; tests that care about single logout ask for one.
    """

    async def work(session: AsyncSession) -> None:
        session.add(
            IdentityProvider(
                slug=scenario.idp_slug,
                name=f"authentik {scenario.suffix}",
                enabled=enabled,
                entity_id=scenario.idp_entity_id,
                sso_url=f"{scenario.idp_entity_id}/sso",
                slo_url=slo_url,
                signing_cert=STUB_CERT,
                want_signed_assertions=True,
            )
        )

    run_db(work)


def seed_request(
    scenario: Scenario,
    *,
    return_to: str = "/users",
    age: dt.timedelta = dt.timedelta(seconds=0),
    relay_state: str | None = None,
    request_id: str | None = None,
) -> None:
    """Write the row /saml/login would have written before the redirect."""
    now = dt.datetime.now(dt.UTC)

    async def work(session: AsyncSession) -> None:
        session.add(
            SamlRequestState(
                relay_state=relay_state or scenario.relay_state,
                request_id=request_id or scenario.request_id,
                idp_slug=scenario.idp_slug,
                return_to=return_to,
                expires_at=now - age + REQUEST_TTL,
            )
        )

    run_db(work)


def good_facts(scenario: Scenario, **overrides: object) -> AssertionFacts:
    """A login that passes every check. Tests break one thing at a time."""
    now = dt.datetime.now(dt.UTC)
    defaults: dict[str, object] = {
        "assertion_id": scenario.assertion_id,
        "issuer": scenario.idp_entity_id,
        "status_code": SAML_SUCCESS,
        "audiences": (OUR_ENTITY_ID,),
        "destination": OUR_ACS_URL,
        "in_response_to": scenario.request_id,
        "not_before": now - dt.timedelta(minutes=1),
        "not_on_or_after": now + dt.timedelta(minutes=5),
        "subject_not_on_or_after": now + dt.timedelta(minutes=5),
        "subject_recipient": OUR_ACS_URL,
        "subject_in_response_to": scenario.request_id,
        "name_id": f"persistent-{scenario.suffix}",
        "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "session_index": f"session-index-{scenario.suffix}",
        "attributes": {
            "http://schemas.goauthentik.io/2021/02/saml/username": [scenario.user_name],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                scenario.user_name
            ],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Ada"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Bergman"],
        },
        "signature_verified": True,
        "assertion_was_signed": True,
    }
    defaults.update(overrides)
    return AssertionFacts(**defaults)  # type: ignore[arg-type]


def logout_request_facts(scenario: Scenario, **overrides: object) -> LogoutRequestFacts:
    """A provider telling us to sign somebody out, and it checks out."""
    defaults: dict[str, object] = {
        "request_id": f"id-logout-{scenario.suffix}",
        "issuer": scenario.idp_entity_id,
        "name_id": f"persistent-{scenario.suffix}",
        "session_index": f"session-index-{scenario.suffix}",
        "was_signed": True,
        "signature_verified": True,
    }
    defaults.update(overrides)
    return LogoutRequestFacts(**defaults)  # type: ignore[arg-type]


def logout_response_facts(scenario: Scenario, **overrides: object) -> LogoutResponseFacts:
    """A provider confirming it signed somebody out because we asked."""
    defaults: dict[str, object] = {
        "response_id": f"id-logout-response-{scenario.suffix}",
        "issuer": scenario.idp_entity_id,
        "status_code": SAML_SUCCESS,
        "was_signed": True,
        "signature_verified": True,
    }
    defaults.update(overrides)
    return LogoutResponseFacts(**defaults)  # type: ignore[arg-type]


def post_login(
    client: TestClient, scenario: Scenario, *, relay_state: str | None = None
) -> httpx.Response:
    data = {"SAMLResponse": POSTED_RESPONSE}
    resolved = scenario.relay_state if relay_state is None else relay_state
    if resolved:
        data["RelayState"] = resolved
    return client.post("/saml/acs", data=data, follow_redirects=False)


def sign_in(client: TestClient, scenario: Scenario, reader: StubReader) -> httpx.Response:
    """The whole login, end to end, leaving the client holding a session cookie."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)
    return post_login(client, scenario)


def fetch_user(scenario: Scenario) -> User | None:
    async def work(session: AsyncSession) -> User | None:
        found: User | None = await session.scalar(
            select(User).where(User.user_name == scenario.user_name)
        )
        return found

    return run_db(work)


def deactivate_user(scenario: Scenario) -> None:
    """Switch this scenario's person off, the way P4's leaver flow will."""

    async def work(session: AsyncSession) -> None:
        user = await session.scalar(select(User).where(User.user_name == scenario.user_name))
        assert user is not None, "nobody has logged in yet, so there is nobody to deactivate"
        user.active = False

    run_db(work)


def fetch_session(scenario: Scenario) -> SamlSession | None:
    async def work(session: AsyncSession) -> SamlSession | None:
        found: SamlSession | None = await session.scalar(
            select(SamlSession).where(SamlSession.idp_slug == scenario.idp_slug)
        )
        return found

    return run_db(work)
