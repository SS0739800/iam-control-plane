"""Tests for reading and signature-checking a real login response.

Everything here is skipped unless xmlsec is importable, which means it runs inside
the container and in the `images` CI job, and skips on Windows. That is the whole
reason the rest of the SAML code is arranged to avoid needing it — but reader.py
does need it, and it is the one module where being wrong means accepting forged
logins, so it cannot go untested.

The response in tests/fixtures/ is a genuine assertion produced by authentik, kept
exactly as it arrived, signed with the certificate next to it. It is a much better
fixture than anything hand-written: hand-written XML tests whatever the author
believed the format to be, and this tests what a real provider actually sends.

Nothing secret is committed. A signed document and a public certificate are both
things a provider hands out, and this one came from a throwaway identity provider
on a laptop.

The assertion has long since expired. That is fine, because nothing here checks
timing — read_response only reads and verifies. Deciding whether a login is
acceptable is checks.py's job and is covered in test_saml_checks.py.
"""

from __future__ import annotations

import base64
import pathlib

import pytest

# Skips the whole module rather than each test. Nothing below can even be imported
# without xmlsec, which has no Windows build. See ADR 0004.
pytest.importorskip("xmlsec", reason="xmlsec only installs in the container")

from iam.saml.checks import MalformedResponse  # noqa: E402
from iam.saml.provisioning import read_claims  # noqa: E402
from iam.saml.reader import (  # noqa: E402
    ASSERTION_SIGNATURE_XPATH,
    RESPONSE_SIGNATURE_XPATH,
    decoded_xml_for_display,
    read_response,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

REAL_RESPONSE = (FIXTURES / "authentik-response.b64").read_text(encoding="utf-8").strip()
AUTHENTIK_CERT = (FIXTURES / "authentik-signing-cert.pem").read_text(encoding="utf-8").strip()
UNRELATED_CERT = (FIXTURES / "unrelated-cert.pem").read_text(encoding="utf-8").strip()


def tampered_response(find: str, replace: str) -> str:
    """The same response with one thing changed, re-encoded.

    The signature covers the assertion, so any change at all has to break it.
    """
    xml = base64.b64decode(REAL_RESPONSE).decode("utf-8")
    assert find in xml, f"{find!r} is not in the fixture, so this test proves nothing"
    return base64.b64encode(xml.replace(find, replace).encode("utf-8")).decode("ascii")


# ------------------------------------------------------------ a real assertion


def test_a_real_authentik_assertion_verifies() -> None:
    facts = read_response(REAL_RESPONSE, AUTHENTIK_CERT)

    assert facts.signature_verified is True


def test_the_assertion_carried_its_own_signature() -> None:
    """Not just the response wrapped around it. Signing only the wrapper leaves the
    contents swappable, and our metadata asks providers not to do that."""
    facts = read_response(REAL_RESPONSE, AUTHENTIK_CERT)

    assert facts.assertion_was_signed is True


def test_the_facts_come_out_of_a_real_assertion() -> None:
    facts = read_response(REAL_RESPONSE, AUTHENTIK_CERT)

    assert facts.assertion_id
    assert facts.issuer == "http://localhost:9000/application/saml/iam-console/"
    assert facts.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    assert "http://localhost:8080/saml/metadata" in facts.audiences
    assert facts.destination == "http://localhost:8080/saml/acs"
    assert facts.in_response_to or facts.subject_in_response_to
    assert facts.not_on_or_after is not None
    assert facts.session_index


def test_the_name_id_is_the_persistent_pseudonym_we_asked_for() -> None:
    """Our AuthnRequest asks for the persistent format, so this should be an opaque
    stable id rather than an email address."""
    facts = read_response(REAL_RESPONSE, AUTHENTIK_CERT)

    assert facts.name_id
    assert facts.name_id_format is not None
    assert "persistent" in facts.name_id_format


def test_provisioning_can_read_a_real_assertion() -> None:
    """The join between the two halves. The claim names in provisioning.py are
    guesses about what providers send until something checks them against a real
    document, and this is that check."""
    claims = read_claims(read_response(REAL_RESPONSE, AUTHENTIK_CERT))

    assert claims.user_name == "akadmin"
    assert claims.email
    assert claims.display_name
    assert claims.external_id


# ------------------------------------------------- signatures that must not pass


def test_our_signature_xpaths_are_the_ones_the_library_expects() -> None:
    """These select the ds:Signature element, not the element it signs.

    Writing the path to the signed thing instead is the mistake that was actually
    made here, and it fails as "signature missing or does not match", which points
    at the certificate rather than at the xpath. Pinning them against the library's
    own constants makes that a test failure instead of an afternoon.
    """
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    assert ASSERTION_SIGNATURE_XPATH == OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH
    assert RESPONSE_SIGNATURE_XPATH == OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH


def test_somebody_elses_certificate_does_not_verify() -> None:
    """A valid certificate that isn't theirs. This is the whole basis of trust: the
    signature has to have been made with the key we were told about."""
    facts = read_response(REAL_RESPONSE, UNRELATED_CERT)

    assert facts.signature_verified is False


def test_changing_who_logged_in_breaks_the_signature() -> None:
    """The attack this stops: take a real login, swap the subject, be somebody else."""
    facts = read_response(
        tampered_response("akadmin", "somebody-else"),
        AUTHENTIK_CERT,
    )

    assert facts.signature_verified is False


def test_changing_the_audience_breaks_the_signature() -> None:
    facts = read_response(
        tampered_response("http://localhost:8080/saml/metadata", "http://evil.example/metadata"),
        AUTHENTIK_CERT,
    )

    assert facts.signature_verified is False


def test_a_garbled_certificate_is_reported_not_raised() -> None:
    """A misconfigured provider must fail the signature check, not take the request
    down with a stack trace."""
    facts = read_response(
        REAL_RESPONSE, "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"
    )

    assert facts.signature_verified is False


# --------------------------------------------------- documents we cannot read


def test_something_that_is_not_base64_is_refused() -> None:
    with pytest.raises(MalformedResponse, match="base64"):
        read_response("this is not base64 !!!", AUTHENTIK_CERT)


def test_something_that_is_not_xml_is_refused() -> None:
    not_xml = base64.b64encode(b"hello, this is not xml").decode("ascii")

    with pytest.raises(MalformedResponse, match="not valid XML"):
        read_response(not_xml, AUTHENTIK_CERT)


def test_a_response_with_no_assertion_is_refused() -> None:
    """A provider reporting failure sends one of these. There is nothing to read a
    person out of, which is different from reading one and rejecting it."""
    empty = base64.b64encode(
        b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
        b"<samlp:Status><samlp:StatusCode "
        b'Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>'
        b"</samlp:Response>"
    ).decode("ascii")

    with pytest.raises(MalformedResponse, match="no assertion"):
        read_response(empty, AUTHENTIK_CERT)


def test_an_oversized_response_is_refused_before_parsing() -> None:
    with pytest.raises(MalformedResponse, match="larger than"):
        read_response("A" * (512 * 1024 + 1), AUTHENTIK_CERT)


def test_an_external_entity_is_not_expanded() -> None:
    """The parser must not fetch or inline anything the document points at. Left on,
    a login form becomes a way to read files off the server.
    """
    xxe = base64.b64encode(
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE r [<!ENTITY secret SYSTEM "file:///etc/hostname">]>'
        b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        b'<saml:Assertion ID="a1"><saml:Issuer>&secret;</saml:Issuer></saml:Assertion>'
        b"</samlp:Response>"
    ).decode("ascii")

    try:
        facts = read_response(xxe, AUTHENTIK_CERT)
    except MalformedResponse:
        # Refusing to parse it at all is the better outcome of the two.
        return

    # If it did parse, the entity must have come to nothing rather than to the
    # contents of a file on disk.
    assert "&secret;" not in facts.issuer
    assert facts.issuer == ""


def test_the_inspector_can_pretty_print_a_real_response() -> None:
    """Shown next to the check results so a person can see what actually arrived."""
    pretty = decoded_xml_for_display(REAL_RESPONSE)

    assert "samlp:Response" in pretty
    assert "\n" in pretty


def test_the_inspector_says_so_rather_than_raising_on_rubbish() -> None:
    assert decoded_xml_for_display("not base64 at all !!") == "(could not be parsed)"
