"""Tests for the documents we publish and the logins we issue.

The escaping tests are the reason this file exists. Everywhere else in the SAML
code we are validating what somebody else signed; here we are signing, and an
assertion we sign is believed by every application holding our certificate. A
display name that can inject XML into it is a way for somebody to grant themselves
attributes, under our signature, with no second opinion anywhere.

The rest checks that we produce what we ourselves demand. checks.py lists ten
things we refuse a login for; an assertion missing any of them would be one our own
service provider rejects, which is the fastest possible way to find out that a
provider asks for more than it gives.

No xmlsec and no database, so these run anywhere. Signing is signer.py's job.
"""

from __future__ import annotations

import datetime as dt
from xml.etree import ElementTree

import pytest

from iam.saml.idp import (
    ASSERTION_LIFETIME,
    CLOCK_SKEW,
    NAMEID_PERSISTENT,
    Issuer,
    LoginToIssue,
    build_failure_response,
    build_response,
    new_id,
    new_session_index,
)

NOW = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC)

ISSUER = Issuer.from_base_url("http://localhost:8080")

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def a_login(**overrides: object) -> LoginToIssue:
    defaults: dict[str, object] = {
        "name_id": "persistent-ada",
        "audience": "https://hrms.demo.local/saml/metadata",
        "acs_url": "https://hrms.demo.local/saml/acs",
        "in_response_to": "id-request-1",
        "issued_at": NOW,
        "session_index": "a-session-index",
        "attributes": {"email": ["ada@demo.local"]},
    }
    defaults.update(overrides)
    return LoginToIssue(**defaults)  # type: ignore[arg-type]


def parsed(xml: str) -> ElementTree.Element:
    """Parse a document we just built ourselves.

    stdlib ElementTree rather than defusedxml, and the input is not untrusted: it is
    the output of the function under test. Parsing it is also the point — an
    assertion that only passes a string comparison could still be malformed, and a
    parser is the thing that would notice.
    """
    return ElementTree.fromstring(xml)  # noqa: S314


# ------------------------------------------------------------------ who we are


def test_the_urls_all_come_from_one_base() -> None:
    """Two places computing these separately is how an entity id ends up with a
    trailing slash in one document and not the other."""
    issuer = Issuer.from_base_url("http://localhost:8080/")

    assert issuer.entity_id == "http://localhost:8080/idp/metadata"
    assert issuer.sso_url == "http://localhost:8080/idp/sso"
    assert issuer.slo_url == "http://localhost:8080/idp/slo"


def test_the_metadata_publishes_the_certificate() -> None:
    """The whole basis of the trust. Everything else in the document is addressing."""
    root = parsed(ISSUER.metadata_xml(certificate_body="MIIFakeCertificateBody"))

    found = root.find(".//ds:X509Certificate", NS)
    assert found is not None
    assert found.text == "MIIFakeCertificateBody"

    descriptor = root.find("./md:IDPSSODescriptor", NS)
    assert descriptor is not None
    key = descriptor.find("./md:KeyDescriptor", NS)
    assert key is not None
    assert key.get("use") == "signing"


def test_the_metadata_offers_both_bindings_for_signing_in() -> None:
    """Redirect is what most providers use; POST is what some insist on. Offering
    only one means an application that wants the other cannot integrate."""
    root = parsed(ISSUER.metadata_xml(certificate_body="MIIFake"))

    bindings = {service.get("Binding") for service in root.findall(".//md:SingleSignOnService", NS)}

    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in bindings
    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in bindings


def test_our_metadata_is_readable_by_our_own_metadata_reader() -> None:
    """The tightest available check that this document is real.

    metadata.py was written to read authentik, Okta and Entra. If it can read ours
    too, then what we publish is the same shape as what actual providers publish —
    and if it cannot, an application using a normal SAML library probably cannot
    either.
    """
    from iam.saml.metadata import read_idp_metadata

    read = read_idp_metadata(ISSUER.metadata_xml(certificate_body="MIIFakeCertificateBody"))

    assert read.entity_id == ISSUER.entity_id
    assert read.sso_url == ISSUER.sso_url
    assert read.slo_url == ISSUER.slo_url
    assert "MIIFakeCertificateBody" in read.signing_cert.replace("\n", "")


# ---------------------------------------------------- what an assertion says


def test_the_response_says_where_it_is_going_and_what_it_answers() -> None:
    root = parsed(build_response(a_login(), issuer=ISSUER))

    assert root.get("Destination") == "https://hrms.demo.local/saml/acs"
    assert root.get("InResponseTo") == "id-request-1"
    assert root.get("Version") == "2.0"

    status = root.find("./samlp:Status/samlp:StatusCode", NS)
    assert status is not None
    assert status.get("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success"


def test_the_assertion_carries_everything_our_own_checks_look_for() -> None:
    """A provider that demands more than it produces is one nobody can integrate
    with — and our own SP is the first thing that will read this."""
    root = parsed(build_response(a_login(), issuer=ISSUER))
    assertion = root.find("./saml:Assertion", NS)
    assert assertion is not None

    # Issuer, so the receiver can tell who signed it.
    issuer_element = assertion.find("./saml:Issuer", NS)
    assert issuer_element is not None
    assert issuer_element.text == ISSUER.entity_id

    # Audience, so it cannot be replayed at a different application.
    audience = assertion.find(".//saml:AudienceRestriction/saml:Audience", NS)
    assert audience is not None
    assert audience.text == "https://hrms.demo.local/saml/metadata"

    # Both time windows: on the Conditions and on the SubjectConfirmationData.
    conditions = assertion.find("./saml:Conditions", NS)
    assert conditions is not None
    assert conditions.get("NotBefore") == "2026-08-19T11:59:00Z"
    assert conditions.get("NotOnOrAfter") == "2026-08-19T12:05:00Z"

    confirmation = assertion.find(".//saml:SubjectConfirmationData", NS)
    assert confirmation is not None
    assert confirmation.get("NotOnOrAfter") == "2026-08-19T12:05:00Z"
    # Recipient is a separate check from Destination in the spec, so both are here.
    assert confirmation.get("Recipient") == "https://hrms.demo.local/saml/acs"
    # And InResponseTo appears in two places, which is also two separate checks.
    assert confirmation.get("InResponseTo") == "id-request-1"

    # A session index, so a logout can name this login.
    statement = assertion.find("./saml:AuthnStatement", NS)
    assert statement is not None
    assert statement.get("SessionIndex") == "a-session-index"


def test_the_timings_leave_room_for_clock_drift() -> None:
    """An assertion that is not valid yet is rejected with a timing error nobody
    thinks to blame on clocks."""
    login = a_login()

    assert login.not_before == NOW - CLOCK_SKEW
    assert login.not_on_or_after == NOW + ASSERTION_LIFETIME


def test_attributes_come_through_with_several_values() -> None:
    """Group membership is the case that matters: one attribute, many values."""
    root = parsed(
        build_response(
            a_login(attributes={"groups": ["Engineering", "VPN Users", "Managers"]}),
            issuer=ISSUER,
        )
    )

    values = [value.text for value in root.findall(".//saml:Attribute/saml:AttributeValue", NS)]

    assert values == ["Engineering", "VPN Users", "Managers"]


def test_a_login_we_started_ourselves_has_no_in_response_to() -> None:
    """Legal, and what an application calls IdP-initiated. Sending an empty
    InResponseTo instead would fail every receiver's check against it."""
    root = parsed(build_response(a_login(in_response_to=None), issuer=ISSUER))

    assert root.get("InResponseTo") is None
    confirmation = root.find(".//saml:SubjectConfirmationData", NS)
    assert confirmation is not None
    assert confirmation.get("InResponseTo") is None


def test_the_name_id_format_is_stated() -> None:
    root = parsed(build_response(a_login(), issuer=ISSUER))

    name_id = root.find(".//saml:NameID", NS)
    assert name_id is not None
    assert name_id.get("Format") == NAMEID_PERSISTENT
    assert name_id.text == "persistent-ada"


# ------------------------------------------------------------------- escaping


def test_a_display_name_cannot_inject_xml() -> None:
    """The one that matters most in this file.

    Somebody who can close a tag inside an assertion we sign can grant themselves
    whatever attributes they like, and every application downstream believes it,
    because the signature is genuine.
    """
    attack = '</saml:AttributeValue></saml:Attribute><saml:Attribute Name="admin">'

    xml = build_response(a_login(attributes={"displayName": [attack]}), issuer=ISSUER)

    # Still one attribute, not two — the injection did not become structure.
    root = parsed(xml)
    names = [attribute.get("Name") for attribute in root.findall(".//saml:Attribute", NS)]
    assert names == ["displayName"]

    # And the text survived intact, as text.
    value = root.find(".//saml:AttributeValue", NS)
    assert value is not None
    assert value.text == attack


def test_an_attribute_name_cannot_inject_xml() -> None:
    """A provider can be configured to send an attribute called anything at all, so
    the names need escaping as much as the values."""
    xml = build_response(a_login(attributes={'x" Name="admin': ["yes"]}), issuer=ISSUER)

    root = parsed(xml)
    names = [attribute.get("Name") for attribute in root.findall(".//saml:Attribute", NS)]
    assert names == ['x" Name="admin']


def test_a_name_id_cannot_inject_xml() -> None:
    xml = build_response(a_login(name_id="</saml:NameID><evil/>"), issuer=ISSUER)

    root = parsed(xml)
    assert root.find(".//evil") is None
    name_id = root.find(".//saml:NameID", NS)
    assert name_id is not None
    assert name_id.text == "</saml:NameID><evil/>"


def test_an_acs_url_with_a_quote_cannot_break_out_of_its_attribute() -> None:
    """The application's own registered value, so lower risk — but it is still data
    somebody typed into a form."""
    xml = build_response(
        a_login(acs_url='https://hrms/acs" Destination="https://evil'), issuer=ISSUER
    )

    root = parsed(xml)
    assert root.get("Destination") == 'https://hrms/acs" Destination="https://evil'


def test_ampersands_in_a_name_survive() -> None:
    """The boring case, and the one that breaks in production. Plenty of real group
    names contain an ampersand."""
    root = parsed(
        build_response(a_login(attributes={"groups": ["Research & Development"]}), issuer=ISSUER)
    )

    value = root.find(".//saml:AttributeValue", NS)
    assert value is not None
    assert value.text == "Research & Development"


# ------------------------------------------------------------- saying no


def test_a_failure_response_has_no_assertion() -> None:
    """Sent instead of an HTTP error so the person lands back at the application
    rather than stranded on our domain with no way onward."""
    xml = build_failure_response(
        issuer=ISSUER,
        acs_url="https://hrms.demo.local/saml/acs",
        in_response_to="id-request-1",
        status_code="urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        message="You do not have access to this application.",
        issued_at=NOW,
    )
    root = parsed(xml)

    assert root.find("./saml:Assertion", NS) is None
    assert root.get("InResponseTo") == "id-request-1"

    message = root.find("./samlp:Status/samlp:StatusMessage", NS)
    assert message is not None
    assert message.text == "You do not have access to this application."


def test_a_failure_message_cannot_inject_xml() -> None:
    xml = build_failure_response(
        issuer=ISSUER,
        acs_url="https://hrms/acs",
        in_response_to=None,
        status_code="urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        message="</samlp:StatusMessage><evil/>",
        issued_at=NOW,
    )

    assert parsed(xml).find(".//evil") is None


# ------------------------------------------------------------------- the ids


@pytest.mark.parametrize("_", range(20))
def test_an_id_never_starts_with_a_digit(_: int) -> None:
    """The schema types these as xs:ID, which may not. A bare UUID starts with a
    digit most of the time, so this would be a bug that appears in roughly 60% of
    logins and works fine in the other 40%."""
    assert not new_id()[0].isdigit()
    assert new_id()[0] == "_"


def test_ids_and_session_indexes_are_unique() -> None:
    assert len({new_id() for _ in range(200)}) == 200
    assert len({new_session_index() for _ in range(200)}) == 200
