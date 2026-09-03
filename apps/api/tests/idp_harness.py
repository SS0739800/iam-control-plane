"""Shared setup for the tests about logins we issue.

Not a test module. The counterpart to saml_harness.py: that one sets up somebody
else asking us to believe them, this one sets up an application asking us to vouch
for somebody.

``StubAuthnReader`` stands in for reading an application's request, since
reader.py needs xmlsec (no Windows build), so the endpoint takes it as a
dependency and a test hands it prepared facts.

``StubSigner`` stands in for xmlsec signing the finished document. It returns
the document unchanged with a marker wrapped around it, so a test can tell
signed from unsigned without verifying anything.

Neither replaces a decision — registration, sign-in, permissions, what the
assertion says, and what gets audited are all real code against a real
database. An actual signature is checked in the container by
test_saml_signer.py.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.application import AppAssignment, Application
from iam.models.enums import AppProtocol, AppStatus, IdentitySource, MembershipSource
from iam.models.group import Group, GroupMember
from iam.models.idp_session import IdpSession
from iam.models.user import User
from iam.saml.checks import AuthnRequestFacts, LogoutRequestFacts
from tests.support import run_db

# The endpoint hands this straight to the stub reader, which ignores it. Still
# real base64 of real-looking XML, since it also travels through a login
# redirect and back in a query string, so it needs to be URL-safe base64.
POSTED_AUTHN_REQUEST = base64.b64encode(
    b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    b"<!-- the reader is stubbed; the facts come from the test -->"
    b"</samlp:AuthnRequest>"
).decode("ascii")

SIGNED_PREFIX = "<!-- signed by the stub signer -->"
"""How a test tells a signed document from an unsigned one.

A marker rather than a real signature, since a real one needs xmlsec. Checks
that the response went through the signing step, since an unsigned assertion
is rejected by every receiver.
"""


class StubAuthnReader:
    """Stands in for reader.py reading an application's login request.

    Hands back facts the test prepared, or raises. Records what it was given, so a
    test can check the endpoint passed the registered certificate rather than
    whatever the request claimed.
    """

    def __init__(self) -> None:
        self.facts: AuthnRequestFacts | None = None
        self.error: Exception | None = None
        self.calls: list[tuple[str, str | None, bool]] = []

    def __call__(
        self, raw: str, sp_signing_cert: str | None = None, *, deflated: bool = True
    ) -> AuthnRequestFacts:
        self.calls.append((raw, sp_signing_cert, deflated))
        if self.error is not None:
            raise self.error
        assert self.facts is not None, "the test did not set up any facts"
        return self.facts


class StubSigner:
    """Stands in for xmlsec signing the finished response.

    Returns the document with a marker in front of it. The key and certificate
    are recorded rather than used, so a test can at least check that the pair
    the app loaded at startup is the pair that got reached for.
    """

    def __init__(self) -> None:
        self.error: Exception | None = None
        self.documents: list[str] = []
        self.keys_seen: list[str] = []

    def __call__(self, response_xml: str, *, private_key_pem: str, certificate_pem: str) -> str:
        self.documents.append(response_xml)
        self.keys_seen.append(private_key_pem)
        if self.error is not None:
            raise self.error
        return f"{SIGNED_PREFIX}{response_xml}"


@dataclass(frozen=True, slots=True)
class AppScenario:
    """One application's worth of test data, with names nothing else will collide with.

    The test database is shared and not reset between tests, and entity_id is unique
    across the whole table — so two tests both registering "https://app.test" would
    pass alone and fail together.
    """

    suffix: str

    @property
    def slug(self) -> str:
        return f"app-{self.suffix}"

    @property
    def name(self) -> str:
        return f"Expenses {self.suffix}"

    @property
    def entity_id(self) -> str:
        return f"https://expenses-{self.suffix}.test/saml/metadata"

    @property
    def acs_url(self) -> str:
        return f"https://expenses-{self.suffix}.test/saml/acs"

    @property
    def slo_url(self) -> str:
        return f"https://expenses-{self.suffix}.test/saml/slo"

    @property
    def other_acs_url(self) -> str:
        """An address the request may ask for and will not get."""
        return f"https://attacker-{self.suffix}.test/collect"

    @property
    def relay_state(self) -> str:
        return f"relay-{self.suffix}"

    @property
    def request_id(self) -> str:
        return f"_id-authn-{self.suffix}"

    @property
    def user_name(self) -> str:
        return f"grace.{self.suffix}@demo.local"

    @property
    def group_name(self) -> str:
        return f"Finance {self.suffix}"

    @property
    def as_user(self) -> dict[str, str]:
        return {"X-Dev-Actor": self.user_name}


def new_app_scenario() -> AppScenario:
    return AppScenario(suffix=uuid.uuid4().hex[:12])


def clean_up(scenario: AppScenario) -> None:
    """Remove everything one test made.

    Assignments first, then what they point at. Audit entries are left behind
    since the table refuses DELETE.
    """

    async def work(session: AsyncSession) -> None:
        application = await session.scalar(
            select(Application).where(Application.slug == scenario.slug)
        )
        if application is not None:
            await session.execute(
                delete(AppAssignment).where(AppAssignment.application_id == application.id)
            )
            await session.execute(delete(Application).where(Application.id == application.id))

        user = await session.scalar(select(User).where(User.user_name == scenario.user_name))
        if user is not None:
            await session.execute(delete(GroupMember).where(GroupMember.user_id == user.id))
            await session.execute(delete(User).where(User.id == user.id))

        await session.execute(delete(Group).where(Group.name == scenario.group_name))

    run_db(work)


def seed_application(
    scenario: AppScenario,
    *,
    status: AppStatus = AppStatus.ACTIVE,
    acs_url: str | None = None,
    entity_id: str | None = None,
    slo_url: str | None = None,
) -> uuid.UUID:
    """Register an application the way the console would."""

    async def work(session: AsyncSession) -> uuid.UUID:
        application = Application(
            name=scenario.name,
            slug=scenario.slug,
            description="Registered by a test",
            protocol=AppProtocol.SAML2,
            status=status,
            entity_id=scenario.entity_id if entity_id is None else entity_id,
            acs_url=scenario.acs_url if acs_url is None else acs_url,
            slo_url=scenario.slo_url if slo_url is None else slo_url,
        )
        session.add(application)
        await session.flush()
        return application.id

    return run_db(work)


def seed_person(scenario: AppScenario, *, active: bool = True) -> uuid.UUID:
    """Somebody to be signed in, with the attributes an assertion carries."""

    async def work(session: AsyncSession) -> uuid.UUID:
        user = User(
            user_name=scenario.user_name,
            email=scenario.user_name,
            display_name=f"Grace Hopper {scenario.suffix}",
            given_name="Grace",
            family_name="Hopper",
            department="Engineering",
            active=active,
            source=IdentitySource.SEED,
        )
        session.add(user)
        await session.flush()
        return user.id

    return run_db(work)


def grant_access(scenario: AppScenario, *, through_group: bool = False) -> None:
    """Give this person access to this application, directly or through a group."""

    async def work(session: AsyncSession) -> None:
        application = await session.scalar(
            select(Application).where(Application.slug == scenario.slug)
        )
        assert application is not None, "no application was seeded"
        user = await session.scalar(select(User).where(User.user_name == scenario.user_name))
        assert user is not None, "nobody was seeded"

        if not through_group:
            session.add(AppAssignment(application_id=application.id, user_id=user.id))
            return

        group = Group(
            name=scenario.group_name,
            description="Created by a test",
            source=IdentitySource.SEED,
        )
        session.add(group)
        await session.flush()
        session.add(GroupMember(group_id=group.id, user_id=user.id, source=MembershipSource.SEED))
        session.add(AppAssignment(application_id=application.id, group_id=group.id))

    run_db(work)


def join_group(scenario: AppScenario) -> None:
    """Put this person in a group without giving that group any access.

    For the test that the group names in an assertion are the person's groups rather
    than only the ones that granted them the application.
    """

    async def work(session: AsyncSession) -> None:
        user = await session.scalar(select(User).where(User.user_name == scenario.user_name))
        assert user is not None, "nobody was seeded"
        group = Group(
            name=scenario.group_name,
            description="Created by a test",
            source=IdentitySource.SEED,
        )
        session.add(group)
        await session.flush()
        session.add(GroupMember(group_id=group.id, user_id=user.id, source=MembershipSource.SEED))

    run_db(work)


def authn_facts(scenario: AppScenario, **overrides: object) -> AuthnRequestFacts:
    """A login request from a registered application. Tests change one thing at a time."""
    defaults: dict[str, object] = {
        "request_id": scenario.request_id,
        "issuer": scenario.entity_id,
        "destination": "http://localhost:8080/idp/sso",
        "acs_url": scenario.acs_url,
        "name_id_policy": None,
        "force_authn": False,
        "relay_state": None,
        "was_signed": False,
        "signature_verified": False,
    }
    defaults.update(overrides)
    return AuthnRequestFacts(**defaults)  # type: ignore[arg-type]


class StubLogoutReader:
    """Stands in for reader.py reading an application's logout request.

    Same seam as StubAuthnReader. Reads nothing: the test says what the message
    contained and whether its signature checked out, and every decision the
    endpoint makes from that is the real code.
    """

    def __init__(self) -> None:
        self.facts: LogoutRequestFacts | None = None
        self.error: Exception | None = None
        self.calls: list[tuple[str, str | None, bool]] = []

    def __call__(
        self, raw: str, signing_cert: str | None = None, *, deflated: bool = True
    ) -> LogoutRequestFacts:
        self.calls.append((raw, signing_cert, deflated))
        if self.error is not None:
            raise self.error
        assert self.facts is not None, "the test did not set up any facts"
        return self.facts


class StubDocumentSigner:
    """Stands in for xmlsec signing a document that has no assertion in it.

    Kept separate from StubSigner because the real functions are separate: one
    of them refuses a document with no assertion, and a single stub with a
    flag would hide that difference from every test.
    """

    def __init__(self) -> None:
        self.error: Exception | None = None
        self.documents: list[str] = []
        self.keys_seen: list[str] = []

    def __call__(self, document_xml: str, *, private_key_pem: str, certificate_pem: str) -> str:
        self.documents.append(document_xml)
        self.keys_seen.append(private_key_pem)
        if self.error is not None:
            raise self.error
        return f"{SIGNED_PREFIX}{document_xml}"


def logout_facts(scenario: AppScenario, **overrides: object) -> LogoutRequestFacts:
    """An application asking us to sign somebody out.

    Names the session index by default, because that is the exact form and the one
    an application that read our assertion would send.
    """
    defaults: dict[str, object] = {
        "request_id": f"_id-logout-{scenario.suffix}",
        "issuer": scenario.entity_id,
        "session_index": None,
        "name_id": None,
        "destination": "http://localhost:8080/idp/slo",
        "was_signed": False,
        "signature_verified": False,
    }
    defaults.update(overrides)
    return LogoutRequestFacts(**defaults)  # type: ignore[arg-type]


def live_idp_sessions(scenario: AppScenario) -> list[tuple[str, str | None]]:
    """The application logins on record for this scenario, and how each ended."""

    async def work(session: AsyncSession) -> list[tuple[str, str | None]]:
        rows = await session.execute(
            select(IdpSession.session_index, IdpSession.ended_reason)
            .join(Application, Application.id == IdpSession.application_id)
            .where(Application.slug == scenario.slug)
            .order_by(IdpSession.issued_at)
        )
        return [(index, reason) for index, reason in rows.tuples().all()]

    return run_db(work)


def session_index_issued(scenario: AppScenario) -> str:
    """The index from the one login on record. Fails loudly if there isn't exactly one."""
    rows = live_idp_sessions(scenario)
    assert len(rows) == 1, f"expected one login on record, found {len(rows)}"
    return rows[0][0]
