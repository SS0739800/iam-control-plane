"""Tests for POST /saml/acs, the endpoint that accepts a login.

These need Postgres, because refusing a login writes an audit entry and accepting
one writes a person and a session. They skip without IAM_TEST_DATABASE_URL, and
CI sets it.

They do not need xmlsec. The endpoint gets the function that reads and
signature-checks a response through a dependency, so a test can hand it prepared
facts and cover everything after that point: the checks, creating the person,
issuing the session, the cookie, and the redirect. Only the signature check
itself is left to the container, which is where it belongs — see ADR 0004 and
ADR 0005.

That is worth being explicit about, because a stub in the wrong place would be a
test that proves nothing. The stub replaces "read this XML and verify it", never
"decide whether this login is acceptable". Every decision below is the real one.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TypeVar

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.db import build_engine, build_sessionmaker
from iam.main import create_app
from iam.models.enums import IdentitySource
from iam.models.saml import IdentityProvider, SamlAssertionSeen, SamlRequestState, SamlSession
from iam.models.user import User
from iam.routers.saml import _response_reader
from iam.saml.checks import SAML_SUCCESS, AssertionFacts, MalformedResponse
from iam.saml.sessions import hash_token
from iam.saml.sp import REQUEST_TTL
from tests.conftest import TEST_DATABASE_ENV_VAR, build_settings

pytestmark = pytest.mark.integration

BASE_URL = "http://localhost:8080"
OUR_ENTITY_ID = f"{BASE_URL}/saml/metadata"
OUR_ACS_URL = f"{BASE_URL}/saml/acs"

# The endpoint never looks at this: the stub reader takes it and hands back
# whatever facts the test set up. It only has to be a non-empty form field.
POSTED_RESPONSE = "not-really-base64-the-reader-is-stubbed"

T = TypeVar("T")


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


def database_url() -> str:
    url = os.environ.get(TEST_DATABASE_ENV_VAR)
    if not url:
        pytest.skip(f"{TEST_DATABASE_ENV_VAR} is not set")
    return url


def run_db(work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    """Run one piece of database work on its own engine, and commit it.

    Its own engine because the app under test has one of its own, running in the
    TestClient's event loop. Sharing a connection across the two would be the
    interesting kind of flaky.
    """

    async def main() -> T:
        engine = build_engine(build_settings(database_url()))
        try:
            async with build_sessionmaker(engine)() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await engine.dispose()

    return asyncio.run(main())


@pytest.fixture
def scenario() -> Iterator[Scenario]:
    """Unique names for one test, and the cleanup afterwards.

    Audit entries are left behind on purpose — the table refuses DELETE, which is
    the point of it.
    """
    made = Scenario(suffix=uuid.uuid4().hex[:12])
    yield made

    async def tidy_up(session: AsyncSession) -> None:
        await session.execute(delete(SamlSession).where(SamlSession.idp_slug == made.idp_slug))
        await session.execute(delete(User).where(User.user_name == made.user_name))
        await session.execute(
            delete(SamlAssertionSeen).where(SamlAssertionSeen.issuer == made.idp_entity_id)
        )
        await session.execute(
            delete(SamlRequestState).where(SamlRequestState.idp_slug == made.idp_slug)
        )
        await session.execute(
            delete(IdentityProvider).where(IdentityProvider.slug == made.idp_slug)
        )

    run_db(tidy_up)


@pytest.fixture
def reader() -> StubReader:
    return StubReader()


@pytest.fixture
def client(reader: StubReader) -> Iterator[TestClient]:
    app = create_app(build_settings(database_url()))
    # Overriding the private dependency directly is deliberate: it is the seam the
    # endpoint was given so that everything downstream of the signature check can
    # be tested without xmlsec.
    app.dependency_overrides[_response_reader] = lambda: reader
    with TestClient(app) as test_client:
        yield test_client


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
                signing_cert="-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
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


def fetch_user(scenario: Scenario) -> User | None:
    async def work(session: AsyncSession) -> User | None:
        found: User | None = await session.scalar(
            select(User).where(User.user_name == scenario.user_name)
        )
        return found

    return run_db(work)


def fetch_session(scenario: Scenario) -> SamlSession | None:
    async def work(session: AsyncSession) -> SamlSession | None:
        found: SamlSession | None = await session.scalar(
            select(SamlSession).where(SamlSession.idp_slug == scenario.idp_slug)
        )
        return found

    return run_db(work)


# ------------------------------------------------- logins we never asked for


def test_a_login_with_no_relay_state_is_refused(client: TestClient, scenario: Scenario) -> None:
    """Nothing ties it to a request we sent, so there is nothing to check it
    against. This is the shape of a login posted at us out of the blue."""
    response = post_login(client, scenario, relay_state="")

    assert response.status_code == 400
    assert "RelayState" in response.json()["detail"]


def test_a_login_we_have_no_record_of_is_refused(client: TestClient, scenario: Scenario) -> None:
    response = post_login(client, scenario, relay_state="a-token-we-never-issued")

    assert response.status_code == 400
    assert "no record" in response.json()["detail"]


def test_an_expired_request_is_refused(client: TestClient, scenario: Scenario) -> None:
    """Ten minutes is enough to type a password. An hour later, no."""
    seed_provider(scenario)
    seed_request(scenario, age=REQUEST_TTL + dt.timedelta(minutes=1))

    response = post_login(client, scenario)

    assert response.status_code == 400
    assert "expired" in response.json()["detail"]


def test_a_provider_turned_off_mid_login_is_refused(client: TestClient, scenario: Scenario) -> None:
    seed_provider(scenario, enabled=False)
    seed_request(scenario)

    response = post_login(client, scenario)

    assert response.status_code == 400
    assert "turned off" in response.json()["detail"]


def test_a_login_that_cannot_be_read_is_refused(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """A 400, not a 401. There was nothing to check, which is different from
    checking it and not liking the answer."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.error = MalformedResponse("response is not valid base64")

    response = post_login(client, scenario)

    assert response.status_code == 400
    assert "could not be read" in response.json()["detail"]


# --------------------------------------------------------- failing the checks


def test_a_login_from_the_wrong_provider_is_refused(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario, issuer="https://somebody-else.test")

    response = post_login(client, scenario)

    assert response.status_code == 401
    assert "issuer" in response.json()["detail"]


def test_a_login_meant_for_another_application_is_refused(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """Without this, anybody with an account on that other application becomes a
    user here."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario, audiences=("https://some-other-app.test/saml/metadata",))

    response = post_login(client, scenario)

    assert response.status_code == 401
    assert "audience" in response.json()["detail"]


def test_an_unsigned_login_is_refused(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario, signature_verified=False)

    response = post_login(client, scenario)

    assert response.status_code == 401
    assert "signature" in response.json()["detail"]
    assert fetch_user(scenario) is None


def test_a_login_answering_a_different_request_is_refused(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """The relay state was ours but the id inside wasn't."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(
        scenario, in_response_to="id-something-else", subject_in_response_to="id-something-else"
    )

    response = post_login(client, scenario)

    assert response.status_code == 401
    assert "in_response_to" in response.json()["detail"]


def test_the_provider_certificate_is_the_one_we_stored(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """The whole basis of trust. Verifying against anything else is verifying
    nothing."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)

    post_login(client, scenario)

    assert reader.certs_seen == ["-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"]


def test_a_refused_login_still_consumes_the_request(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """One answer per request, right or wrong.

    Leave the request open after a failure and a captured login can be retried
    until something lines up. This is the test that says it can't be.
    """
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario, issuer="https://somebody-else.test")

    first = post_login(client, scenario)
    reader.facts = good_facts(scenario)
    second = post_login(client, scenario)

    assert first.status_code == 401
    assert second.status_code == 400
    assert "no record" in second.json()["detail"]


# ------------------------------------------------------------- a good login


def test_a_good_login_signs_the_person_in(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario, return_to="/users")
    reader.facts = good_facts(scenario)

    response = post_login(client, scenario)

    assert response.status_code == 303
    assert response.headers["location"] == "/users"


def test_a_good_login_sets_a_locked_down_cookie(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """httponly so a scripting bug can't read it, samesite so another site can't
    ride on it. Lax rather than strict, or the person lands back here still
    looking logged out."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)

    response = post_login(client, scenario)

    set_cookie = response.headers["set-cookie"]
    assert "iam_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("samesite", "SameSite")
    assert "Path=/" in set_cookie


def test_the_cookie_value_is_not_what_gets_stored(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """Only the hash is written down, the same way passwords are handled. Someone
    who reads the sessions table still can't sign in as anybody."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)

    response = post_login(client, scenario)
    token = response.cookies["iam_session"]

    stored = fetch_session(scenario)
    assert stored is not None
    assert stored.token_hash == hash_token(token)
    assert stored.token_hash != token


def test_a_good_login_records_what_the_provider_called_the_session(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """Needed later so "they signed out over there" can be matched to a session
    here."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)

    post_login(client, scenario)

    stored = fetch_session(scenario)
    assert stored is not None
    assert stored.session_index == f"session-index-{scenario.suffix}"
    assert stored.name_id == f"persistent-{scenario.suffix}"


def test_a_first_login_creates_the_person(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)

    post_login(client, scenario)

    created = fetch_user(scenario)
    assert created is not None
    assert created.display_name == "Ada Bergman"
    assert created.source is IdentitySource.JIT


def test_an_unsafe_return_path_falls_back_to_the_home_page(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """Checked on the way in as well. This is the second look, so a tampered-with
    row can't turn a successful login into a redirect to somebody else's site."""
    seed_provider(scenario)
    seed_request(scenario, return_to="//evil.example")
    reader.facts = good_facts(scenario)

    response = post_login(client, scenario)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_a_deactivated_person_cannot_log_in(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """The provider will happily sign someone in who we've switched off. Ours is
    the answer that counts, and P4 leans on this holding."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)
    post_login(client, scenario)

    async def deactivate(session: AsyncSession) -> None:
        user = await session.scalar(select(User).where(User.user_name == scenario.user_name))
        assert user is not None
        user.active = False

    run_db(deactivate)

    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    reader.facts = good_facts(
        scenario,
        assertion_id=f"{scenario.assertion_id}-2",
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
    )
    response = post_login(client, scenario, relay_state=f"{scenario.relay_state}-2")

    assert response.status_code == 403
    assert "deactivated" in response.json()["detail"]


def test_the_same_login_cannot_be_used_twice(
    client: TestClient, scenario: Scenario, reader: StubReader
) -> None:
    """A captured login is otherwise good until it expires. Note this needs a
    second request state to get past the one-answer-per-request rule, which is
    exactly the situation replay protection exists for: everything else about the
    second attempt is fine."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)
    first = post_login(client, scenario)

    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    reader.facts = good_facts(
        scenario,
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
    )
    second = post_login(client, scenario, relay_state=f"{scenario.relay_state}-2")

    assert first.status_code == 303
    assert second.status_code == 401
    assert "not_replayed" in second.json()["detail"]
