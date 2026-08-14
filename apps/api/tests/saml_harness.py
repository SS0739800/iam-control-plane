"""Shared setup for the SAML endpoint tests.

Not a test module. It holds the pieces that both the assertion-consumer tests and
the sign-out tests need: unique names for one run, a stand-in for the reader, and
the seeding and querying helpers.

The stub reader is the important thing to understand. reader.py is the only
module that needs xmlsec and so the only one that can't be imported here or in
CI. The endpoint takes it as a dependency, so these tests hand it prepared facts
and exercise everything after the signature check for real: the ten checks,
creating the person, the session, the cookie, the redirect.

That is a stub in the one place a stub is safe. It replaces "read this XML and
verify it", never "decide whether this login is acceptable".
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.saml import IdentityProvider, SamlAssertionSeen, SamlRequestState, SamlSession
from iam.models.user import User
from iam.saml.checks import SAML_SUCCESS, AssertionFacts
from iam.saml.sp import REQUEST_TTL
from tests.support import run_db

BASE_URL = "http://localhost:8080"
OUR_ENTITY_ID = f"{BASE_URL}/saml/metadata"
OUR_ACS_URL = f"{BASE_URL}/saml/acs"

STUB_CERT = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"

# The endpoint never looks at this: the stub reader takes it and hands back
# whatever facts the test set up. It only has to be a non-empty form field.
POSTED_RESPONSE = "not-really-base64-the-reader-is-stubbed"


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


def new_scenario() -> Scenario:
    return Scenario(suffix=uuid.uuid4().hex[:12])


def clean_up(scenario: Scenario) -> None:
    """Remove everything one test made.

    Audit entries are left behind on purpose — the table refuses DELETE, which is
    the point of it.
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


def seed_provider(scenario: Scenario, *, enabled: bool = True) -> None:
    async def work(session: AsyncSession) -> None:
        session.add(
            IdentityProvider(
                slug=scenario.idp_slug,
                name=f"authentik {scenario.suffix}",
                enabled=enabled,
                entity_id=scenario.idp_entity_id,
                sso_url=f"{scenario.idp_entity_id}/sso",
                slo_url=None,
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
