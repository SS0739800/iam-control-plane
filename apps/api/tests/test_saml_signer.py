"""Tests for signing the messages we issue.

Skipped unless xmlsec is importable, so this runs in the container and in
the `images` CI job and skips on Windows — same arrangement as
test_saml_reader.py, same reason: signing is the one thing on this side
that genuinely needs the native library.

The test that matters most is the round trip: sign an assertion here, then
read it back with our own service provider reader from P2 and confirm the
signature verifies. Those two halves were written against the spec rather
than against each other, so if they interoperate, the document is very
likely real, not just plausible.

The second most important is where the signature lands. Signing the
response instead of the assertion is a change nobody would notice, the
login still works, but it leaves the part carrying the claims unprotected
the moment a receiver pulls the assertion out on its own.
"""

from __future__ import annotations

import base64
import datetime as dt

import pytest

# Skips the whole module rather than each test: nothing below imports without
# xmlsec, which has no Windows build. See ADR 0004.
pytest.importorskip("xmlsec", reason="xmlsec only installs in the container")

from lxml import etree  # noqa: E402

from iam.saml.idp import (  # noqa: E402
    Issuer,
    LoginToIssue,
    build_failure_response,
    build_logout_response,
    build_response,
)
from iam.saml.keys import generate  # noqa: E402
from iam.saml.reader import read_logout_response, read_response  # noqa: E402
from iam.saml.signer import SigningFailed, sign_assertion, sign_document  # noqa: E402

ISSUER = Issuer.from_base_url("http://localhost:8080")

# One keypair for the module. Generating RSA keys is slow enough to notice
# if every test made its own, and nothing here depends on them differing.
PAIR = generate(common_name="http://localhost:8080")
OTHER_PAIR = generate(common_name="http://localhost:8080")

ISSUED_AT = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC)

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def a_login(**overrides: object) -> LoginToIssue:
    defaults: dict[str, object] = {
        "name_id": "persistent-ada",
        "audience": "http://localhost:8080/saml/metadata",
        "acs_url": "http://localhost:8080/saml/acs",
        "in_response_to": "id-request-1",
        "attributes": {"email": ["ada@demo.local"], "groups": ["Engineering", "VPN Users"]},
    }
    defaults.update(overrides)
    return LoginToIssue(**defaults)  # type: ignore[arg-type]


def sign(login: LoginToIssue | None = None, *, pair: object = PAIR) -> str:
    return sign_assertion(
        build_response(login or a_login(), issuer=ISSUER),
        private_key_pem=pair.private_key_pem,  # type: ignore[attr-defined]
        certificate_pem=pair.certificate_pem,  # type: ignore[attr-defined]
    )


# ------------------------------------------------------- where the signature goes


def test_the_signature_is_inside_the_assertion() -> None:
    """Signing the response instead would still produce a working login, but
    would leave the claims unprotected the moment a receiver reads the
    assertion alone — the signature-wrapping shape reader.py refuses from
    the other side."""
    root = etree.fromstring(sign().encode())  # noqa: S320

    parents = [
        etree.QName(signature.getparent()).localname
        for signature in root.findall(".//ds:Signature", NS)
    ]

    assert parents == ["Assertion"]


def test_the_certificate_travels_with_the_signature() -> None:
    """So a receiver can see which key was used, rather than guessing between the
    two we might have published during a rotation."""
    root = etree.fromstring(sign().encode())  # noqa: S320

    embedded = root.find(".//ds:Signature//ds:X509Certificate", NS)
    assert embedded is not None
    assert embedded.text is not None
    assert embedded.text.replace("\n", "") in PAIR.certificate_body


def test_signing_uses_sha256_not_sha1() -> None:
    """SHA-1 is still the default in several libraries and gets refused by
    current versions of the same libraries on the receiving side. Being
    explicit is what stops a login that works today failing after somebody
    else upgrades."""
    signed = sign()

    assert "rsa-sha256" in signed
    assert "xmlenc#sha256" in signed or "xmldsig-more#rsa-sha256" in signed
    assert "rsa-sha1" not in signed


# --------------------------------------------------- the round trip that matters


def test_our_own_reader_verifies_our_own_signature() -> None:
    """The strongest evidence available that what we issue is real.

    The reader was written in P2 against the spec, the signer in P5 against
    the spec, neither against the other. If they interoperate, the
    document is very likely correct, not just plausible.
    """
    signed = sign()

    facts = read_response(base64.b64encode(signed.encode()).decode(), PAIR.certificate_pem)

    assert facts.signature_verified is True
    assert facts.assertion_was_signed is True


def test_every_field_survives_the_round_trip() -> None:
    """Signing must not disturb the content, and reinserting the signed assertion
    into the response must not either."""
    signed = sign()

    facts = read_response(base64.b64encode(signed.encode()).decode(), PAIR.certificate_pem)

    assert facts.issuer == ISSUER.entity_id
    assert facts.audiences == ("http://localhost:8080/saml/metadata",)
    assert facts.destination == "http://localhost:8080/saml/acs"
    assert facts.in_response_to == "id-request-1"
    assert facts.name_id == "persistent-ada"
    assert facts.attributes["email"] == ["ada@demo.local"]
    assert facts.attributes["groups"] == ["Engineering", "VPN Users"]


def test_a_different_certificate_does_not_verify() -> None:
    """The check is real, not a formality. Without this the round trip above could
    pass while verifying nothing."""
    signed = sign()

    facts = read_response(base64.b64encode(signed.encode()).decode(), OTHER_PAIR.certificate_pem)

    assert facts.signature_verified is False


def test_tampering_with_the_assertion_breaks_the_signature() -> None:
    """The reason to sign it: changing a single attribute value after the
    fact has to be detectable."""
    signed = sign().replace("ada@demo.local", "attacker@evil.test")

    facts = read_response(base64.b64encode(signed.encode()).decode(), PAIR.certificate_pem)

    assert facts.signature_verified is False


def test_an_ampersand_in_a_group_name_survives_signing() -> None:
    """Escaped on the way in, unescaped on the way out, and the signature covers
    the escaped form. Easy to get right in one place and wrong in the other."""
    signed = sign(a_login(attributes={"groups": ["Research & Development"]}))

    facts = read_response(base64.b64encode(signed.encode()).decode(), PAIR.certificate_pem)

    assert facts.signature_verified is True
    assert facts.attributes["groups"] == ["Research & Development"]


def test_an_injection_attempt_survives_as_text_and_stays_signed() -> None:
    """The escaping test from test_saml_idp.py, carried through signing:
    escaping that held in the builder could still be undone by a round
    trip through lxml."""
    attack = '</saml:AttributeValue></saml:Attribute><saml:Attribute Name="admin">'
    signed = sign(a_login(attributes={"displayName": [attack]}))

    facts = read_response(base64.b64encode(signed.encode()).decode(), PAIR.certificate_pem)

    assert facts.signature_verified is True
    assert facts.attributes["displayName"] == [attack]
    assert "admin" not in facts.attributes


# -------------------------------------------------------------- refusing to sign


def test_a_response_with_no_assertion_is_refused() -> None:
    """A failure response has no assertion, and signing shouldn't quietly
    do nothing when there's nothing to sign."""
    failure = build_failure_response(
        issuer=ISSUER,
        acs_url="http://localhost:8080/saml/acs",
        in_response_to="id-request-1",
        status_code="urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        message="No access to this application.",
    )

    with pytest.raises(SigningFailed, match="no assertion"):
        sign_assertion(
            failure,
            private_key_pem=PAIR.private_key_pem,
            certificate_pem=PAIR.certificate_pem,
        )


def test_a_document_that_is_not_xml_is_refused() -> None:
    with pytest.raises(SigningFailed, match="not valid XML"):
        sign_assertion(
            "this is not xml",
            private_key_pem=PAIR.private_key_pem,
            certificate_pem=PAIR.certificate_pem,
        )


def test_a_bad_key_raises_rather_than_returning_an_unsigned_document() -> None:
    """An unsigned assertion looks almost identical and gets rejected by the
    receiver with a signature error, which sends whoever's debugging it to
    the wrong end of the connection."""
    with pytest.raises(SigningFailed, match="refused to sign"):
        sign_assertion(
            build_response(a_login(), issuer=ISSUER),
            private_key_pem="-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----",
            certificate_pem=PAIR.certificate_pem,
        )


# ------------------------------------------- signing a document with no assertion


def a_logout_confirmation() -> str:
    """An unsigned LogoutResponse, for the tests below to sign."""
    return build_logout_response(
        issuer=ISSUER,
        destination="https://expenses.test/saml/slo",
        in_response_to="_id-logout-1",
        issued_at=ISSUED_AT,
    )


def test_a_logout_confirmation_signs_and_verifies() -> None:
    """The same round trip as the assertion one, for the other kind of message.

    Signed here with sign_document, then read back by the reader our own
    service provider uses for a provider's logout confirmation. Both halves
    were written against the spec, not against each other.
    """
    signed = sign_document(
        a_logout_confirmation(),
        private_key_pem=PAIR.private_key_pem,
        certificate_pem=PAIR.certificate_pem,
    )

    facts = read_logout_response(
        base64.b64encode(signed.encode("utf-8")).decode("ascii"),
        PAIR.certificate_pem,
        deflated=False,
    )

    assert facts.was_signed is True
    assert facts.signature_verified is True
    assert facts.in_response_to == "_id-logout-1"
    assert facts.status_code.endswith(":Success")


def test_a_logout_confirmation_does_not_verify_with_a_different_key() -> None:
    """Otherwise the test above proves only that a signature is present."""
    signed = sign_document(
        a_logout_confirmation(),
        private_key_pem=PAIR.private_key_pem,
        certificate_pem=PAIR.certificate_pem,
    )

    facts = read_logout_response(
        base64.b64encode(signed.encode("utf-8")).decode("ascii"),
        OTHER_PAIR.certificate_pem,
        deflated=False,
    )

    assert facts.was_signed is True
    assert facts.signature_verified is False


def test_the_signature_lands_on_the_root_of_a_logout_confirmation() -> None:
    """There's nothing nested here to protect, so the root is the right thing.

    Worth pinning, since the assertion signer does the opposite. The two
    behaving the same way would mean one of them was wrong.
    """
    signed = sign_document(
        a_logout_confirmation(),
        private_key_pem=PAIR.private_key_pem,
        certificate_pem=PAIR.certificate_pem,
    )

    # Our own freshly signed output, not untrusted input.
    root = etree.fromstring(signed.encode("utf-8"))  # noqa: S320
    signatures = root.findall("{http://www.w3.org/2000/09/xmldsig#}Signature")

    assert len(signatures) == 1, "exactly one signature, directly on the root"


def test_the_assertion_signer_refuses_a_logout_confirmation() -> None:
    """Why the two functions are separate rather than one with a flag.

    sign_assertion looks for an assertion and refuses when there's none,
    which is what stops it signing a wrapper and leaving claims unprotected.
    A LogoutResponse has no assertion, so it has to be refused here and
    routed to sign_document.
    """
    with pytest.raises(SigningFailed, match="no assertion"):
        sign_assertion(
            a_logout_confirmation(),
            private_key_pem=PAIR.private_key_pem,
            certificate_pem=PAIR.certificate_pem,
        )


def test_signing_something_that_is_not_xml_is_refused() -> None:
    with pytest.raises(SigningFailed, match="not valid XML"):
        sign_document(
            "this is not xml",
            private_key_pem=PAIR.private_key_pem,
            certificate_pem=PAIR.certificate_pem,
        )
