"""Tests for /idp/slo — an application telling us somebody signed out.

This endpoint was advertised in our metadata before it existed. It couldn't
have been written earlier: the SessionIndex we put in every assertion was
generated fresh and never stored, so a logout request quoting one had
nothing to match. The first test below is the one that would have failed
then and passes now.

Not tested here: fan-out to the other applications somebody is signed into,
since it isn't built. The last test pins that gap in place rather than
leaving it to a docstring — if somebody implements fan-out, that test
should fail and get rewritten.

No xmlsec: the reader and the signer are the two seams. Needs Postgres.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.saml.checks import MalformedResponse
from tests.idp_harness import (
    SIGNED_PREFIX,
    AppScenario,
    StubAuthnReader,
    StubDocumentSigner,
    StubSigner,
    authn_facts,
    grant_access,
    live_idp_sessions,
    logout_facts,
    seed_application,
    seed_person,
    session_index_issued,
)
from tests.idp_harness import StubLogoutReader as StubIdpLogoutReader
from tests.support import run_db

pytestmark = pytest.mark.integration

SSO = "/idp/sso"
SLO = "/idp/slo"

# The endpoint never reads this: the stub returns whatever facts the test set up. It
# only has to be a non-empty query parameter.
POSTED_REQUEST = "not-really-deflated-the-reader-is-stubbed"


def latest_logout_detail() -> dict[str, Any]:
    """The detail on the most recent logout audit entry."""

    async def work(session: AsyncSession) -> dict[str, Any]:
        found = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "idp.logout_received")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert found is not None, "no logout was recorded"
        detail: dict[str, Any] = found.detail
        return detail

    return run_db(work)


def sign_in(client: TestClient, scenario: AppScenario, reader: StubAuthnReader) -> None:
    """Put one login on record, the way an application would."""
    reader.facts = authn_facts(scenario)
    response = client.get(
        SSO,
        params={"SAMLRequest": POSTED_REQUEST, "RelayState": scenario.relay_state},
        headers=scenario.as_user,
        follow_redirects=False,
    )
    assert response.status_code == 200, response.text[:300]


# ------------------------------------------------------ matching the request


def test_a_logout_naming_our_session_index_ends_that_login(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """The test that could not have passed before idp_sessions existed.

    We issued the index, so an application quoting it names exactly one login at
    exactly one application. Nothing looser is needed and nothing looser is used.
    """
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    sign_in(idp_client, app_scenario, authn_reader)

    issued = session_index_issued(app_scenario)
    assert live_idp_sessions(app_scenario) == [(issued, None)]

    idp_logout_reader.facts = logout_facts(app_scenario, session_index=issued)
    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 303
    assert live_idp_sessions(app_scenario) == [(issued, "application_signed_out")]


def test_a_logout_naming_only_the_subject_still_works(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """A request is allowed to name only the NameID, and some applications do."""
    seed_application(app_scenario)
    user_id = seed_person(app_scenario)
    grant_access(app_scenario)
    sign_in(idp_client, app_scenario, authn_reader)

    idp_logout_reader.facts = logout_facts(app_scenario, name_id=str(user_id))
    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 303
    assert live_idp_sessions(app_scenario)[0][1] == "application_signed_out"


def test_a_logout_for_somebody_with_no_login_still_answers_success(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """The application asked for the person to be signed out. They are.

    A failure would invite it to retry something with nothing left to do, and some
    implementations retry in a loop.
    """
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 303


def test_the_confirmation_goes_to_the_registered_logout_address(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """The same rule as the assertion: the registered address, never one from the
    message."""
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.headers["location"].startswith(app_scenario.slo_url)
    assert "SAMLResponse=" in response.headers["location"]


def test_the_relay_state_comes_back_unchanged(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """Opaque to us, and the application needs it to resume what it was doing."""
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    response = idp_client.get(
        SLO,
        params={"SAMLRequest": POSTED_REQUEST, "RelayState": app_scenario.relay_state},
        follow_redirects=False,
    )

    assert app_scenario.relay_state in response.headers["location"]


# --------------------------------------------------------- what it refuses


def test_a_logout_with_no_request_is_refused(idp_client: TestClient) -> None:
    response = idp_client.get(SLO, follow_redirects=False)

    assert response.status_code == 400
    assert "No SAMLRequest" in response.json()["detail"]


def test_an_unreadable_request_is_an_http_error(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """The one refusal that cannot be SAML: with nothing readable there is no issuer,
    so there is no address to send a LogoutResponse to."""
    seed_application(app_scenario)
    idp_logout_reader.error = MalformedResponse("not valid base64")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 400
    assert "could not be read" in response.json()["detail"]


def test_a_logout_from_an_unregistered_application_is_refused(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """Anybody can send one of these. Without a registered application there is no
    trusted address to reply to, and using the one from the message is the mistake
    this whole surface refuses to make."""
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="anything")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 404


def test_an_application_with_no_logout_address_is_refused(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """Registered, but nowhere to send the confirmation."""
    seed_application(app_scenario, slo_url="")
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="anything")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 404


def test_one_application_cannot_sign_somebody_out_of_another(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """A subject-only request is narrowed to the application that asked.

    Without that narrowing, one application naming a NameID could close somebody's
    login at another — which is not its business to ask for.
    """
    seed_application(app_scenario)
    user_id = seed_person(app_scenario)
    grant_access(app_scenario)
    sign_in(idp_client, app_scenario, authn_reader)

    # A second, unrelated application asks us to sign the same person out.
    other = AppScenario(suffix=uuid.uuid4().hex[:12])
    seed_application(other)
    idp_logout_reader.facts = logout_facts(other, name_id=str(user_id))

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 303
    # The first application's login is untouched.
    assert live_idp_sessions(app_scenario)[0][1] is None


# ------------------------------------------------------------- the signing


def test_the_confirmation_is_signed_with_the_loaded_keypair(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
    document_signer: StubDocumentSigner,
) -> None:
    """A test cannot check a signature without xmlsec, but it can check the pair the
    app loaded at startup is the pair that was reached for — which is the part that
    would go wrong silently."""
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert len(document_signer.documents) == 1
    assert "<samlp:LogoutResponse" in document_signer.documents[0]
    assert document_signer.keys_seen[0].startswith("-----BEGIN")


def test_the_assertion_signer_is_not_used_for_a_logout(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
    assertion_signer: StubSigner,
    document_signer: StubDocumentSigner,
) -> None:
    """The two signers are separate because one refuses a document with no assertion.

    A LogoutResponse has none, so routing it through the assertion signer would fail
    — and a single signer with a flag would have hidden that.
    """
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert document_signer.documents, "the document signer should have been used"
    assert not assertion_signer.documents, "the assertion signer must not be used here"


def test_a_signing_failure_is_not_sent_as_an_unsigned_confirmation(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
    document_signer: StubDocumentSigner,
) -> None:
    """An unsigned confirmation looks almost identical and is rejected at the far end
    with a signature error, which sends whoever is debugging to the wrong system."""
    from iam.saml.idp import SigningFailed

    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")
    document_signer.error = SigningFailed("xmlsec said no")

    response = idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 500
    assert SIGNED_PREFIX not in response.text


# ------------------------------------------------------------ the POST binding


def test_the_post_binding_works_too(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    response = idp_client.post(SLO, data={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    assert response.status_code == 303


def test_each_binding_decodes_the_way_its_binding_says(
    idp_client: TestClient,
    app_scenario: AppScenario,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """Redirect deflates, POST does not. Getting this backwards produces a decode
    error that reads like a broken application."""
    seed_application(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index="never-issued")

    idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)
    idp_client.post(SLO, data={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    deflated_flags = [deflated for _, _, deflated in idp_logout_reader.calls]
    assert deflated_flags == [True, False]


# ------------------------------------------------------------- the known gap


def test_the_other_applications_are_not_notified_yet(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    idp_logout_reader: StubIdpLogoutReader,
) -> None:
    """Pins a gap in place rather than leaving it in a docstring.

    Signing out at one application doesn't tell the others. The table now
    makes fan-out possible (one browser session, several rows, each naming
    an address), but it isn't built, and the audit entry says so explicitly
    so anybody auditing a logout can see it.

    If somebody implements fan-out, this test should fail — that's what
    it's for.
    """
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    sign_in(idp_client, app_scenario, authn_reader)

    issued = session_index_issued(app_scenario)
    idp_logout_reader.facts = logout_facts(app_scenario, session_index=issued)
    idp_client.get(SLO, params={"SAMLRequest": POSTED_REQUEST}, follow_redirects=False)

    detail = latest_logout_detail()

    assert detail["matched"] is True
    assert detail["other_applications_notified"] is False
