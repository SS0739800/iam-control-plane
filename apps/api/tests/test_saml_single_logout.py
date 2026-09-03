"""Tests for single logout, in both directions.

Two different things arrive at /saml/sls and they are easy to conflate:

A `SAMLResponse` is the provider confirming it did what we asked. Our
session ended before we asked, so there's nothing left to do.

A `SAMLRequest` is the provider telling us to sign somebody out. That's the
reason single logout matters: it's what makes "remove their access" reach
sessions somebody already has, not just ones they start later.

These need Postgres and skip without IAM_TEST_DATABASE_URL. Reading the XML
is stubbed — see tests/saml_harness.py for what that does and doesn't
replace — and the real thing is checked against a live authentik by
scripts/smoke_login.py.
"""

from __future__ import annotations

import base64
import zlib
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.models.saml import SamlRequestState, SamlSession
from iam.saml.sessions import RevokedReason
from tests.saml_harness import (
    STUB_CERT,
    Scenario,
    StubLogoutReader,
    StubReader,
    fetch_session,
    good_facts,
    logout_request_facts,
    logout_response_facts,
    post_login,
    seed_provider,
    seed_request,
)
from tests.support import run_db

pytestmark = pytest.mark.integration

IDP_SLO_URL = "https://authentik.test/application/saml/iam/slo/binding/redirect/"

# The endpoint hands whatever arrives to the stub, so it only has to be present.
POSTED_MESSAGE = "not-really-a-logout-message-the-reader-is-stubbed"

NOBODY = {"X-Dev-Actor": "nobody-with-this-name@demo.local"}


def sign_in_with_slo(
    client: TestClient, scenario: Scenario, reader: StubReader, *, slo_url: str | None = IDP_SLO_URL
) -> None:
    """A completed login against a provider that has a logout address."""
    seed_provider(scenario, slo_url=slo_url)
    seed_request(scenario)
    reader.facts = good_facts(scenario)
    assert post_login(client, scenario).status_code == 303


def logout_request_xml(location: str) -> str:
    """Pull our LogoutRequest back out of the redirect we sent the browser to."""
    query = parse_qs(urlparse(location).query)
    return zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -zlib.MAX_WBITS).decode(
        "utf-8"
    )


def latest_action() -> str:
    async def work(session: AsyncSession) -> str:
        event = await session.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        assert event is not None
        return str(event.action)

    return run_db(work)


# ------------------------------------------------------- we start the logout


def test_signing_out_sends_the_provider_a_logout_request(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Otherwise clicking login again puts them straight back in with no password,
    because the provider still thinks they're signed in."""
    sign_in_with_slo(saml_client, scenario, saml_reader)

    response = saml_client.post("/saml/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith(IDP_SLO_URL)


def test_the_logout_request_names_the_person_and_the_session(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The NameID says who, the SessionIndex says which of their sessions. Leaving
    the index out asks the provider to end all of them."""
    sign_in_with_slo(saml_client, scenario, saml_reader)

    response = saml_client.post("/saml/logout", follow_redirects=False)
    xml = logout_request_xml(response.headers["location"])

    assert "<samlp:LogoutRequest" in xml
    assert f"persistent-{scenario.suffix}" in xml
    assert f"session-index-{scenario.suffix}" in xml
    assert "http://localhost:8080/saml/metadata" in xml


def test_our_session_ends_before_the_provider_is_asked(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """If the provider is down or never answers, the person still has to be signed
    out here. That part is ours."""
    sign_in_with_slo(saml_client, scenario, saml_reader)

    saml_client.post("/saml/logout", follow_redirects=False)

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_reason == RevokedReason.SIGNED_OUT
    assert saml_client.get("/api/me", headers=NOBODY).status_code == 401


def test_a_provider_with_no_logout_address_just_sends_them_home(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Plenty of providers have none. Signing out still works, it just doesn't
    reach them."""
    sign_in_with_slo(saml_client, scenario, saml_reader, slo_url=None)

    response = saml_client.post("/saml/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_the_logout_request_is_written_down_so_the_answer_can_be_matched(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    sign_in_with_slo(saml_client, scenario, saml_reader)

    response = saml_client.post("/saml/logout", follow_redirects=False)
    relay_state = parse_qs(urlparse(response.headers["location"]).query)["RelayState"][0]

    async def work(session: AsyncSession) -> SamlRequestState | None:
        found: SamlRequestState | None = await session.scalar(
            select(SamlRequestState).where(SamlRequestState.relay_state == relay_state)
        )
        return found

    stored = run_db(work)
    assert stored is not None
    assert stored.idp_slug == scenario.idp_slug


# --------------------------------------------- the provider answers our request


def test_their_confirmation_consumes_the_request_and_sends_them_home(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_response_reader: StubLogoutReader,
) -> None:
    sign_in_with_slo(saml_client, scenario, saml_reader)
    started = saml_client.post("/saml/logout", follow_redirects=False)
    relay_state = parse_qs(urlparse(started.headers["location"]).query)["RelayState"][0]

    saml_logout_response_reader.facts = logout_response_facts(scenario)
    response = saml_client.get(
        "/saml/sls",
        params={"SAMLResponse": POSTED_MESSAGE, "RelayState": relay_state},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"

    async def work(session: AsyncSession) -> int:
        rows = (
            await session.scalars(
                select(SamlRequestState).where(SamlRequestState.relay_state == relay_state)
            )
        ).all()
        return len(rows)

    assert run_db(work) == 0


def test_a_confirmation_we_were_not_waiting_for_is_harmless(
    saml_client: TestClient, scenario: Scenario
) -> None:
    """Nothing to match it to, and nothing to undo. Sending the person home beats
    an error page about a message they never saw."""
    response = saml_client.get(
        "/saml/sls",
        params={"SAMLResponse": POSTED_MESSAGE, "RelayState": "never-issued"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"


# ------------------------------------------- the provider starts the logout


def test_a_signed_logout_request_ends_the_session_it_names(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """The message that makes "remove their access" reach a session somebody
    already has."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario)

    response = saml_client.get(
        "/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False
    )

    assert response.status_code == 303

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_reason == RevokedReason.SIGNED_OUT_ELSEWHERE
    assert saml_client.get("/api/me", headers=NOBODY).status_code == 401


def test_it_is_checked_against_the_certificate_we_stored(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """Which provider sent it is decided by whose key signed it, not by the Issuer
    field — that's a line in an unverified document."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario)

    saml_client.get("/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False)

    assert STUB_CERT in saml_logout_reader.certs_seen


def test_a_request_with_no_session_index_ends_all_of_their_sessions(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """What an absent index asks for, and the right reading for "this account is
    gone" rather than "this person pressed sign out on one device"."""
    sign_in_with_slo(saml_client, scenario, saml_reader)

    # A second session for the same person, as if from another device.
    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    saml_reader.facts = good_facts(
        scenario,
        assertion_id=f"{scenario.assertion_id}-2",
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
        session_index=f"session-index-{scenario.suffix}-other",
    )
    post_login(saml_client, scenario, relay_state=f"{scenario.relay_state}-2")

    saml_logout_reader.facts = logout_request_facts(scenario, session_index=None)
    saml_client.get("/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False)

    async def work(session: AsyncSession) -> list[SamlSession]:
        rows = (
            await session.scalars(
                select(SamlSession).where(SamlSession.idp_slug == scenario.idp_slug)
            )
        ).all()
        return list(rows)

    sessions = run_db(work)
    assert len(sessions) == 2
    assert all(row.revoked_at is not None for row in sessions)


def test_an_unsigned_logout_request_is_refused(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """We can't tell who sent it, and accepting it would let anybody sign out
    anybody whose NameID they can guess."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(
        scenario, was_signed=False, signature_verified=False
    )

    response = saml_client.get(
        "/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False
    )

    assert response.status_code == 400
    assert "not signed by a provider we know" in response.json()["detail"]

    still_there = fetch_session(scenario)
    assert still_there is not None
    assert still_there.revoked_at is None


def test_a_request_signed_by_a_key_we_do_not_know_is_refused(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario, signature_verified=False)

    response = saml_client.get(
        "/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False
    )

    assert response.status_code == 400
    assert fetch_session(scenario) is not None


def test_a_refused_logout_request_is_recorded(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """Somebody trying to sign our users out is worth being able to see."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario, signature_verified=False)

    saml_client.get("/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False)

    assert latest_action() == "saml.logout_request_refused"


def test_we_answer_the_provider_that_asked(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """It's waiting to hear that we did it."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario)

    response = saml_client.get(
        "/saml/sls",
        params={"SAMLRequest": POSTED_MESSAGE, "RelayState": "their-token"},
        follow_redirects=False,
    )

    location = response.headers["location"]
    assert location.startswith(IDP_SLO_URL)

    query = parse_qs(urlparse(location).query)
    assert query["RelayState"] == ["their-token"]
    xml = zlib.decompress(base64.b64decode(query["SAMLResponse"][0]), -zlib.MAX_WBITS).decode(
        "utf-8"
    )
    assert "<samlp:LogoutResponse" in xml
    assert 'InResponseTo="id-logout-' in xml
    assert "urn:oasis:names:tc:SAML:2.0:status:Success" in xml


def test_a_logout_request_for_somebody_with_no_session_still_answers(
    saml_client: TestClient,
    scenario: Scenario,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """From the provider's point of view the person is signed out of this
    application either way, which is what it asked for."""
    seed_provider(scenario, slo_url=IDP_SLO_URL)
    saml_logout_reader.facts = logout_request_facts(scenario)

    response = saml_client.get(
        "/saml/sls", params={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(IDP_SLO_URL)


def test_the_post_binding_works_the_same_way(
    saml_client: TestClient,
    scenario: Scenario,
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
) -> None:
    """Providers differ on which method they use and the message is identical."""
    sign_in_with_slo(saml_client, scenario, saml_reader)
    saml_logout_reader.facts = logout_request_facts(scenario)

    response = saml_client.post(
        "/saml/sls", data={"SAMLRequest": POSTED_MESSAGE}, follow_redirects=False
    )

    assert response.status_code == 303

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_at is not None


def test_a_request_carrying_no_message_at_all_is_a_400(saml_client: TestClient) -> None:
    response = saml_client.get("/saml/sls", follow_redirects=False)

    assert response.status_code == 400
    assert "SAMLRequest" in response.json()["detail"]
