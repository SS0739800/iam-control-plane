"""Reads a login response and checks its signature.

This is the only file that touches XML or cryptography, which is why it's the only
one that needs xmlsec, and so the only one that can't run on Windows. Everything
that decides whether to accept a login lives in checks.py and stays testable
anywhere. See docs/adr/0005-validate-assertions-ourselves.md.

Two things here are security-relevant rather than just plumbing:

The parser is locked down. Untrusted XML with entity expansion turned on lets
someone read files off the server or hang the process, and the defaults in most XML
libraries allow it. See SAFE_PARSER.

The signature is checked against the assertion element specifically, not just
whatever signature happens to be in the document. A response can carry more than
one, and verifying the wrong one is how signature-wrapping attacks work.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import logging
from typing import Any

from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from iam.saml.checks import AssertionFacts, MalformedResponse

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_RESPONSE_BYTES",
    "SAFE_PARSER",
    "MalformedResponse",
    "decode_response",
    "decoded_xml_for_display",
    "parse",
    "read_response",
]

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

SAFE_PARSER = etree.XMLParser(
    # Without this, a login response can define an entity pointing at a local file
    # and have its contents pasted into the document. That's how you read
    # /etc/passwd through a login form.
    resolve_entities=False,
    # Stops the parser fetching anything referenced in the document.
    no_network=True,
    # Refuses documents built to blow up in memory when expanded.
    huge_tree=False,
    load_dtd=False,
    dtd_validation=False,
)

MAX_RESPONSE_BYTES = 512 * 1024
"""Refuse anything absurdly large before parsing it. A real login response is a
few kilobytes; anything approaching this is either broken or deliberate."""

# These point at the ds:Signature element, not at the element it signs, and that
# distinction is the whole reason they're named constants with a comment.
#
# validate_sign() takes an xpath and treats whatever it selects as the signature
# node. Handing it "/samlp:Response/saml:Assertion" — the thing being signed,
# which is what you would write if you were describing intent — makes it try to
# read an Assertion element as a signature. That fails, and it fails as
# "signature missing or does not match", which points at the certificate and not
# at the xpath. Cost an afternoon against a real authentik.
ASSERTION_SIGNATURE_XPATH = "/samlp:Response/saml:Assertion/ds:Signature"
RESPONSE_SIGNATURE_XPATH = "/samlp:Response/ds:Signature"


def decode_response(raw: str) -> bytes:
    """Turn the base64 form field into XML bytes."""
    if len(raw) > MAX_RESPONSE_BYTES:
        raise MalformedResponse(f"response larger than {MAX_RESPONSE_BYTES} bytes")

    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedResponse("response is not valid base64") from exc


def parse(xml: bytes) -> etree._Element:
    """Parse the XML with entity expansion and network access turned off."""
    try:
        # S320 warns about parsing untrusted XML with lxml, which is a fair warning
        # in general. SAFE_PARSER above is the mitigation it's asking for: entity
        # expansion off, no network, no oversized trees. Don't remove the noqa
        # without also checking SAFE_PARSER is still doing its job.
        root = etree.fromstring(xml, parser=SAFE_PARSER)  # noqa: S320
    except etree.XMLSyntaxError as exc:
        raise MalformedResponse(f"response is not valid XML: {exc}") from exc

    if root is None:
        raise MalformedResponse("response is empty")
    return root


def _text(element: etree._Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    stripped = element.text.strip()
    return stripped or None


def _parse_instant(value: str | None) -> dt.datetime | None:
    """Read a SAML timestamp.

    These are always UTC in practice. Anything without a timezone is treated as
    UTC rather than as local time, because guessing local time here would make the
    timing checks wrong in a way that only shows up in some deployments.
    """
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("saml.unreadable_timestamp", extra={"value": value})
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def _first(root: etree._Element, path: str) -> etree._Element | None:
    found = root.findall(path, NS)
    return found[0] if found else None


def _signature_over(element: etree._Element) -> bool:
    """Whether this element carries a signature of its own, not a child's.

    The './' matters. Without it this would also find a signature nested deeper and
    report the wrong thing.
    """
    return len(element.findall("./ds:Signature", NS)) > 0


def _verify(xml: bytes, cert: str, xpath: str) -> bool:
    """Check one signature against the provider's certificate.

    The xpath matters. A response can contain several signed pieces, and verifying
    "a signature" rather than "the signature over the thing I'm about to read" is
    the gap signature-wrapping attacks go through. The caller says which signature
    it means, and it has to be a path to a ds:Signature element — see
    ASSERTION_SIGNATURE_XPATH.

    Leaving the xpath off would let the library pick, and it prefers the signature
    over the whole response. That is the one we specifically do not want to rely
    on, so it is always passed.

    python3-saml does the actual work here, wrapping xmlsec and OpenSSL. Do not
    replace this with anything hand-written.
    """
    try:
        return bool(
            OneLogin_Saml2_Utils.validate_sign(
                xml,
                cert=cert,
                validatecert=False,
                raise_exceptions=False,
                xpath=xpath,
            )
        )
    except Exception:
        # A bad signature throws in a variety of ways depending on how it's broken.
        # All of them mean the same thing here, and none of them should take the
        # request down.
        logger.warning("saml.signature_check_failed", exc_info=True)
        return False


def read_response(raw_response: str, idp_signing_cert: str) -> AssertionFacts:
    """Pull the facts out of a login response and check its signature.

    Reads and verifies. It does not decide anything: whether to accept the login is
    checks.py's job, working from what this returns.

    Raises:
        MalformedResponse: There was no readable response to check.
    """
    xml = decode_response(raw_response)
    root = parse(xml)

    assertion = _first(root, "./saml:Assertion")
    if assertion is None:
        # Could be an encrypted assertion, which P2 does not handle yet, or a
        # response carrying only an error status.
        if _first(root, "./saml:EncryptedAssertion") is not None:
            raise MalformedResponse("encrypted assertions are not supported yet")
        raise MalformedResponse("response contains no assertion")

    assertion_id = assertion.get("ID")
    if not assertion_id:
        raise MalformedResponse("assertion has no ID, so it cannot be replay-checked")

    status_code_el = _first(root, "./samlp:Status/samlp:StatusCode")
    status_code = status_code_el.get("Value", "") if status_code_el is not None else ""

    issuer = _text(_first(assertion, "./saml:Issuer")) or _text(_first(root, "./saml:Issuer")) or ""

    conditions = _first(assertion, "./saml:Conditions")
    audiences = tuple(
        value
        for value in (
            _text(el)
            for el in (
                conditions.findall("./saml:AudienceRestriction/saml:Audience", NS)
                if conditions is not None
                else []
            )
        )
        if value
    )

    subject_confirmation_data = _first(
        assertion,
        "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData",
    )

    name_id_el = _first(assertion, "./saml:Subject/saml:NameID")

    # The provider's name for this login session. Needed later so that "someone
    # signed out over there" can be matched to a session here.
    session_index = None
    for statement in assertion.findall("./saml:AuthnStatement", NS):
        session_index = statement.get("SessionIndex")
        if session_index:
            break

    attributes: dict[str, list[str]] = {}
    for attribute in assertion.findall("./saml:AttributeStatement/saml:Attribute", NS):
        name = attribute.get("Name")
        if not name:
            continue
        values = [
            text
            for text in (_text(el) for el in attribute.findall("./saml:AttributeValue", NS))
            if text
        ]
        attributes[name] = values

    # Verify the signature over the assertion, because the assertion is what we
    # read the person's identity out of. If it isn't signed itself, fall back to
    # the signature over the whole response, and record which it was so
    # check_assertion_signed can object.
    assertion_was_signed = _signature_over(assertion)
    if assertion_was_signed:
        signature_verified = _verify(xml, idp_signing_cert, ASSERTION_SIGNATURE_XPATH)
    else:
        signature_verified = _verify(xml, idp_signing_cert, RESPONSE_SIGNATURE_XPATH)

    return AssertionFacts(
        assertion_id=assertion_id,
        issuer=issuer,
        status_code=status_code,
        audiences=audiences,
        destination=root.get("Destination"),
        in_response_to=root.get("InResponseTo"),
        not_before=_parse_instant(conditions.get("NotBefore") if conditions is not None else None),
        not_on_or_after=_parse_instant(
            conditions.get("NotOnOrAfter") if conditions is not None else None
        ),
        subject_not_on_or_after=_parse_instant(
            subject_confirmation_data.get("NotOnOrAfter")
            if subject_confirmation_data is not None
            else None
        ),
        subject_recipient=(
            subject_confirmation_data.get("Recipient")
            if subject_confirmation_data is not None
            else None
        ),
        subject_in_response_to=(
            subject_confirmation_data.get("InResponseTo")
            if subject_confirmation_data is not None
            else None
        ),
        name_id=_text(name_id_el),
        name_id_format=name_id_el.get("Format") if name_id_el is not None else None,
        session_index=session_index,
        attributes=attributes,
        signature_verified=signature_verified,
        assertion_was_signed=assertion_was_signed,
    )


def decoded_xml_for_display(raw_response: str) -> str:
    """Pretty-printed XML for the login inspector.

    Shown so a person can look at what actually arrived. Safe to display: it's the
    provider's own document, and it's already been through the locked-down parser.
    """
    try:
        root = parse(decode_response(raw_response))
    except MalformedResponse:
        return "(could not be parsed)"
    pretty: Any = etree.tostring(root, pretty_print=True, encoding="unicode")
    return str(pretty)
