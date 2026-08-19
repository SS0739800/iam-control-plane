"""Tests for the logins we issue to applications.

The other direction from test_saml_acs.py. There we were checking somebody else's
word; here an application takes ours, and an assertion we sign is believed by
everything holding our certificate with no second opinion anywhere.

Three tests earn the file on their own:

*The address in the request is ignored.* An AuthnRequest names where to send the
answer, and honouring it hands whoever sent it a genuine signed assertion for
whoever happened to be logged in. The registered address is the only one used, and
`test_the_address_in_the_request_is_never_used` is what stops that quietly changing.

*Nobody gets an assertion without an assignment.* This is where P4's entitlements
stop being a report and start being enforcement.

*A refusal comes back as SAML.* Somebody halfway through signing in should land at
the application with something it can explain, not on our domain looking at an error
page — and the audit log should say why.

Reading the request and signing the response are stubbed, because both need xmlsec.
Everything between them — registered, signed in, allowed, what the assertion says,
what is written down — is the real code against a real database. See
tests/idp_harness.py for exactly what the stubs replace.
"""

from __future__ import annotations

import base64
import re
import uuid
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.models.enums import AppStatus, AuditOutcome
from iam.saml.checks import MalformedResponse
from iam.saml.idp import SigningFailed
from tests.idp_harness import (
    POSTED_AUTHN_REQUEST,
    SIGNED_PREFIX,
    AppScenario,
    StubAuthnReader,
    StubSigner,
    authn_facts,
    grant_access,
    join_group,
    seed_application,
    seed_person,
)
from tests.support import run_db

pytestmark = pytest.mark.integration

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
STATUS_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
STATUS_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"


# --------------------------------------------------------------- reading the reply


def form_action(html: str) -> str:
    """Where the auto-submitting form posts to."""
    found = re.search(r'<form method="post" action="([^"]*)"', html)
    assert found is not None, f"no form in the response:\n{html}"
    return found.group(1)


def hidden_field(html: str, name: str) -> str | None:
    """One hidden input's value, as it appears in the HTML."""
    found = re.search(rf'name="{name}" value="([^"]*)"', html)
    return found.group(1) if found else None


def saml_response(html: str) -> str:
    """The response document the form is carrying, decoded."""
    encoded = hidden_field(html, "SAMLResponse")
    assert encoded is not None, f"no SAMLResponse in the response:\n{html}"
    return base64.b64decode(encoded).decode("utf-8")


def parsed(html: str) -> ElementTree.Element:
    """The response document, ready to be looked into.

    The signing stub puts a marker in front of the document, so this strips it —
    which also means a test asserting on the XML cannot accidentally pass on
    something that was never signed.
    """
    document = saml_response(html)
    return ElementTree.fromstring(document.removeprefix(SIGNED_PREFIX))  # noqa: S314


def attributes_in(assertion: ElementTree.Element) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for attribute in assertion.findall(".//saml:Attribute", NS):
        name = attribute.get("Name")
        assert name is not None
        found[name] = [value.text or "" for value in attribute.findall("./saml:AttributeValue", NS)]
    return found


def status_codes(document: ElementTree.Element) -> tuple[str | None, str | None]:
    """The two status codes in a refusal, outer first.

    SAML nests them: the outer one says whose fault it is, and the inner one says
    what happened. Reading only the first is how a test ends up asserting on
    "Responder" and passing whatever the actual reason turns out to be.
    """
    outer = document.find(".//samlp:Status/samlp:StatusCode", NS)
    if outer is None:
        return None, None
    inner = outer.find("./samlp:StatusCode", NS)
    return outer.get("Value"), (inner.get("Value") if inner is not None else None)


def latest_audit(action: str, application_id: uuid.UUID) -> AuditEvent:
    async def work(session: AsyncSession) -> AuditEvent:
        found = await session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action == action,
                AuditEvent.target_id == str(application_id),
            )
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert found is not None, f"nothing was written for {action}"
        return found

    return run_db(work)


def start_login(
    client: TestClient,
    scenario: AppScenario,
    reader: StubAuthnReader,
    *,
    relay_state: str | None = None,
    signed_in_as: str | None = None,
    **fact_overrides: object,
) -> str:
    """The whole thing: an application asks, and somebody is signed in.

    Returns the response body, which is either the posting form or the redirect to
    log in first.
    """
    reader.facts = authn_facts(scenario, **fact_overrides)
    params = {"SAMLRequest": POSTED_AUTHN_REQUEST}
    if relay_state:
        params["RelayState"] = relay_state
    headers = {"X-Dev-Actor": signed_in_as} if signed_in_as else scenario.as_user
    response = client.get("/idp/sso", params=params, headers=headers, follow_redirects=False)
    assert response.status_code == 200, response.text
    return response.text


# ------------------------------------------------------- before anything is signed


def test_an_unreadable_request_is_refused_here_rather_than_posted_anywhere(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """No readable request means no issuer, so no application, so no address.

    The one refusal that has to be an HTTP error: there is nowhere to post a SAML
    failure to, and the address in the request is exactly the thing we will not use.
    """
    seed_application(app_scenario)
    authn_reader.error = MalformedResponse("authn request has no ID")

    response = idp_client.get(
        "/idp/sso",
        params={"SAMLRequest": POSTED_AUTHN_REQUEST},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "could not be read" in response.text
    assert assertion_signer.documents == []


def test_an_application_nobody_registered_gets_nothing(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """An entity id is a claim about who is asking, and it is looked up, not believed."""
    seed_person(app_scenario)
    authn_reader.facts = authn_facts(app_scenario, issuer="https://nobody-registered.test")

    response = idp_client.get(
        "/idp/sso",
        params={"SAMLRequest": POSTED_AUTHN_REQUEST},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 404
    assert "https://nobody-registered.test" in response.text
    assert assertion_signer.documents == []


def test_a_switched_off_application_stops_issuing_logins(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Switching an application off is how access is cut for everybody at once.

    It has to stop logins, not just hide the row in the console — otherwise the
    switch does nothing that matters.
    """
    seed_application(app_scenario, status=AppStatus.INACTIVE)
    seed_person(app_scenario)
    grant_access(app_scenario)
    authn_reader.facts = authn_facts(app_scenario)

    response = idp_client.get(
        "/idp/sso",
        params={"SAMLRequest": POSTED_AUTHN_REQUEST},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 404


# ------------------------------------------------------------- logging in first


def test_somebody_not_signed_in_is_sent_to_log_in_and_comes_back(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """The whole point of single sign-on: log in once, then carry on where you were.

    The header names somebody who does not exist, which is how this gets a 401
    whatever DEV_ACTOR_USER_NAME happens to be set to.
    """
    seed_application(app_scenario)
    authn_reader.facts = authn_facts(app_scenario)

    response = idp_client.get(
        "/idp/sso",
        params={"SAMLRequest": POSTED_AUTHN_REQUEST, "RelayState": app_scenario.relay_state},
        headers={"X-Dev-Actor": "nobody.at.all@demo.local"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = urlparse(response.headers["location"])
    assert location.path == "/saml/login"

    return_to = parse_qs(location.query)["return_to"][0]
    coming_back = parse_qs(urlparse(return_to).query)
    assert urlparse(return_to).path == "/idp/sso"
    # Both of these have to survive, and they are what the old unencoded version
    # lost: the request itself, and the state the application asked us to hand back.
    assert coming_back["SAMLRequest"] == [POSTED_AUTHN_REQUEST]
    assert coming_back["RelayState"] == [app_scenario.relay_state]


def test_a_posted_request_survives_the_trip_through_logging_in(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """A login is a redirect, and a redirect is a GET, so the POST body is gone.

    The request travels back in the query string instead, with a note that it was
    never deflated — without which it would come back unreadable, and the endpoint
    would work only for people who happened to be signed in already.
    """
    seed_application(app_scenario)
    authn_reader.facts = authn_facts(app_scenario)

    response = idp_client.post(
        "/idp/sso",
        data={"SAMLRequest": POSTED_AUTHN_REQUEST},
        headers={"X-Dev-Actor": "nobody.at.all@demo.local"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    return_to = parse_qs(urlparse(response.headers["location"]).query)["return_to"][0]
    coming_back = parse_qs(urlparse(return_to).query)
    assert coming_back["SAMLRequest"] == [POSTED_AUTHN_REQUEST]
    assert coming_back["binding"] == ["post"]


def test_the_request_coming_back_is_read_as_undeflated(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """The other half of the trip above: the note is acted on, not just written."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    authn_reader.facts = authn_facts(app_scenario)

    idp_client.get(
        "/idp/sso",
        params={"SAMLRequest": POSTED_AUTHN_REQUEST, "binding": "post"},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    _, _, deflated = authn_reader.calls[-1]
    assert deflated is False


def test_a_deactivated_person_is_refused_rather_than_sent_round_the_login_again(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """ "Not signed in" and "signed in, account switched off" are opposite answers.

    Sending a leaver to log in would be a loop with no exit, and it would tell them
    nothing. The application is told instead, in SAML, and nothing is signed.
    """
    application_id = seed_application(app_scenario)
    seed_person(app_scenario, active=False)
    grant_access(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader)

    assert form_action(html) == app_scenario.acs_url
    assert status_codes(parsed(html)) == (STATUS_RESPONDER, STATUS_DENIED)
    assert assertion_signer.documents == []

    entry = latest_audit("idp.login_refused", application_id)
    assert entry.outcome == AuditOutcome.DENIED


# ----------------------------------------------------------------- who may sign in


def test_nobody_gets_a_login_without_an_assignment(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """Where P4 stops being a report.

    A real person, signed in, at a real application, refused because nothing grants
    them access to it.
    """
    application_id = seed_application(app_scenario)
    seed_person(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader)

    document = parsed(html)
    assert status_codes(document) == (STATUS_RESPONDER, STATUS_DENIED)
    assert document.find(".//saml:Assertion", NS) is None
    assert assertion_signer.documents == []

    entry = latest_audit("idp.login_refused", application_id)
    assert entry.outcome == AuditOutcome.DENIED
    assert entry.detail is not None
    assert app_scenario.slug in str(entry.detail)


def test_a_refusal_says_which_application_it_was(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """The message reaches somebody who cannot fix it themselves, so it has to name
    the thing they will be asking about."""
    seed_application(app_scenario)
    seed_person(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader)

    message = parsed(html).find(".//samlp:StatusMessage", NS)
    assert message is not None and message.text is not None
    assert app_scenario.name in message.text


def test_a_direct_assignment_is_enough(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader)

    assert parsed(html).find(".//saml:Assertion", NS) is not None


def test_access_through_a_group_is_enough(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Almost all real access is granted this way, so this is the path that matters."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario, through_group=True)

    html = start_login(idp_client, app_scenario, authn_reader)

    assert parsed(html).find(".//saml:Assertion", NS) is not None


# -------------------------------------------------------------- where it is posted


def test_the_address_in_the_request_is_never_used(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """The worst mistake available on this endpoint, and the reason for the file.

    Anybody can send a request naming a real application and their own return
    address. Honouring it would deliver a genuine signed assertion, for whoever
    happened to be logged in, to a server the sender chose.
    """
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader, acs_url=app_scenario.other_acs_url)

    assert form_action(html) == app_scenario.acs_url
    assert app_scenario.other_acs_url not in html

    # And the assertion says the same thing, because a receiver checks Recipient
    # against its own address rather than against where the form pointed.
    recipient = parsed(html).find(".//saml:SubjectConfirmationData", NS)
    assert recipient is not None
    assert recipient.get("Recipient") == app_scenario.acs_url


def test_a_refusal_goes_to_the_registered_address_too(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """The refusal path is the easier one to forget, and it posts a document too."""
    seed_application(app_scenario)
    seed_person(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader, acs_url=app_scenario.other_acs_url)

    assert form_action(html) == app_scenario.acs_url


# ---------------------------------------------------------------- what it contains


def test_the_assertion_answers_the_request_that_asked(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """InResponseTo is how an application knows this is the answer to its own
    request rather than one somebody replayed at it."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    document = parsed(start_login(idp_client, app_scenario, authn_reader))

    assert document.get("InResponseTo") == app_scenario.request_id
    confirmation = document.find(".//saml:SubjectConfirmationData", NS)
    assert confirmation is not None
    assert confirmation.get("InResponseTo") == app_scenario.request_id


def test_the_name_id_is_the_persons_id_rather_than_their_email(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Emails change. An application keying its records on one is how somebody ends
    up with two accounts after they change their name."""
    seed_application(app_scenario)
    user_id = seed_person(app_scenario)
    grant_access(app_scenario)

    name_id = parsed(start_login(idp_client, app_scenario, authn_reader)).find(".//saml:NameID", NS)

    assert name_id is not None
    assert name_id.text == str(user_id)


def test_the_attributes_are_the_small_set_an_application_needs(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Every attribute here is one more thing an application starts depending on."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    released = attributes_in(parsed(start_login(idp_client, app_scenario, authn_reader)))

    assert released["email"] == [app_scenario.user_name]
    assert released["userName"] == [app_scenario.user_name]
    assert released["givenName"] == ["Grace"]
    assert released["surname"] == ["Hopper"]
    assert released["department"] == ["Engineering"]


def test_group_names_travel_with_the_login(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """How an application does its own authorisation without asking us a second time.

    The group here grants nothing, which is the point: the attribute is who this
    person is, not how they got in.
    """
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    join_group(app_scenario)

    released = attributes_in(parsed(start_login(idp_client, app_scenario, authn_reader)))

    assert released["groups"] == [app_scenario.group_name]


def test_the_relay_state_comes_back_unchanged(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Opaque to us. It is how the application resumes whatever it was doing."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader, relay_state=app_scenario.relay_state)

    assert hidden_field(html, "RelayState") == app_scenario.relay_state


def test_a_relay_state_cannot_break_out_of_its_attribute(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """RelayState is data somebody else chose, landing inside a quoted HTML
    attribute on a page that submits itself. An unescaped quote there is a script
    running in the browser of somebody midway through signing in."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    html = start_login(
        idp_client,
        app_scenario,
        authn_reader,
        relay_state='"><script>alert(1)</script>',
    )

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_the_response_was_actually_signed(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """An unsigned assertion looks almost identical and is rejected by everything."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    html = start_login(idp_client, app_scenario, authn_reader)

    assert saml_response(html).startswith(SIGNED_PREFIX)
    assert assertion_signer.keys_seen == [idp_client.app.state.saml_keypair.private_key_pem]  # type: ignore[attr-defined]


def test_a_login_that_cannot_be_signed_is_refused_rather_than_sent_unsigned(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
) -> None:
    """Sending it anyway would put the confusing error at their end rather than ours."""
    application_id = seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    assertion_signer.error = SigningFailed("no key")

    html = start_login(idp_client, app_scenario, authn_reader)

    document = parsed(html)
    assert status_codes(document) == (STATUS_RESPONDER, STATUS_UNSUPPORTED)
    assert document.find(".//saml:Assertion", NS) is None

    entry = latest_audit("idp.login_refused", application_id)
    assert entry.outcome == AuditOutcome.DENIED


# --------------------------------------------------------------------- the record


def test_an_issued_login_is_written_down(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Who was let into what, and when. The entry an access review is read from."""
    application_id = seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    start_login(idp_client, app_scenario, authn_reader)

    entry = latest_audit("idp.login_issued", application_id)
    assert entry.outcome == AuditOutcome.SUCCESS
    assert entry.target_label == app_scenario.slug
    assert app_scenario.user_name in (entry.actor_label or "")


def test_the_record_names_the_attributes_without_repeating_them(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Which attributes were released is the reviewable fact. Their values are
    somebody's personal details, and the audit log is not the place for a second
    copy of them."""
    application_id = seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    start_login(idp_client, app_scenario, authn_reader)

    detail = latest_audit("idp.login_issued", application_id).detail
    assert detail is not None
    assert "email" in detail["attributes_released"]
    assert app_scenario.user_name not in str(detail["attributes_released"])


# ------------------------------------------------------- logins we start ourselves


def test_a_login_we_start_has_no_request_to_answer(
    idp_client: TestClient,
    app_scenario: AppScenario,
) -> None:
    """Clicking an application in the console. Legal SAML — the assertion simply
    carries no InResponseTo, because no request asked for it."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    response = idp_client.get(
        "/idp/sso",
        params={"app": app_scenario.slug},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 200
    document = parsed(response.text)
    assert document.get("InResponseTo") is None
    assert document.find(".//saml:Assertion", NS) is not None


def test_the_tidy_link_signs_somebody_in_the_same_way(
    idp_client: TestClient,
    app_scenario: AppScenario,
) -> None:
    """So the console can link to an application without building a query string."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)

    response = idp_client.get(
        f"/idp/sso/{app_scenario.slug}",
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert parsed(response.text).find(".//saml:Assertion", NS) is not None


def test_a_login_we_start_still_checks_access(
    idp_client: TestClient,
    app_scenario: AppScenario,
) -> None:
    """The console-initiated path is the easy one to leave unguarded, because the
    person clicking is already signed in."""
    seed_application(app_scenario)
    seed_person(app_scenario)

    response = idp_client.get(
        f"/idp/sso/{app_scenario.slug}",
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert status_codes(parsed(response.text)) == (STATUS_RESPONDER, STATUS_DENIED)


# ------------------------------------------------------------------- both bindings


def test_the_post_binding_issues_the_same_login(
    idp_client: TestClient,
    app_scenario: AppScenario,
    authn_reader: StubAuthnReader,
) -> None:
    """Our metadata offers both, and an application that reads metadata and finds
    only one of them working has been lied to."""
    seed_application(app_scenario)
    seed_person(app_scenario)
    grant_access(app_scenario)
    authn_reader.facts = authn_facts(app_scenario)

    response = idp_client.post(
        "/idp/sso",
        data={"SAMLRequest": POSTED_AUTHN_REQUEST, "RelayState": app_scenario.relay_state},
        headers=app_scenario.as_user,
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert parsed(response.text).find(".//saml:Assertion", NS) is not None
    assert hidden_field(response.text, "RelayState") == app_scenario.relay_state

    _, _, deflated = authn_reader.calls[-1]
    assert deflated is False
