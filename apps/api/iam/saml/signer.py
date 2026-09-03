"""Signing the logins we issue.

The counterpart to reader.py, and like it, the only thing in this direction
that needs xmlsec, so the only part of the identity-provider side that can't
run on Windows. Everything about what an assertion says lives in idp.py and
stays testable anywhere.

The signature goes over the assertion element, not the response wrapping it.
Both are legal and providers differ, but signing only the response leaves the
assertion unprotected against a receiver that pulls it out and reads it on its
own — the same signature-wrapping shape reader.py refuses on the other side of
this. Signing the assertion protects the part carrying the claims, wherever it
ends up. We sign the assertion, which is also what authentik, Okta, and Entra
do by default.

python3-saml's ``add_sign`` finds the first ``//saml:Issuer`` in whatever it's
given and signs that issuer's parent. Handed a whole response, that's the
response's own issuer, so it would sign the response instead of the
assertion. That's why the assertion is pulled out, signed on its own, and put
back. That's safe because the signature uses exclusive canonicalisation,
which omits namespace declarations the subtree inherits but doesn't use, so
moving the element back into the response doesn't change what was signed.

Everything else in the document has to be final first: the signature covers
the canonicalised element, so one attribute added afterwards invalidates it.
That's why this takes a finished document and returns a finished document
rather than offering a builder.
"""

from __future__ import annotations

import logging

from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from iam.saml.idp import SigningFailed
from iam.saml.reader import SAFE_PARSER

logger = logging.getLogger(__name__)

# SigningFailed is raised here and defined in idp.py, which needs no xmlsec, so
# the endpoint that catches it stays importable on a laptop. Re-exported so this
# module still reads as the one place signing goes wrong.
__all__ = ["SigningFailed", "sign_assertion"]

ASSERTION_TAG = f"{{{OneLogin_Saml2_Constants.NS_SAML}}}Assertion"


def sign_assertion(response_xml: str, *, private_key_pem: str, certificate_pem: str) -> str:
    """Sign the assertion inside a response, and return the whole document.

    Args:
        response_xml: A complete, final response document. Nothing may be changed
            afterwards — the signature covers the canonicalised element, so one
            added attribute invalidates it.
        private_key_pem: The key to sign with.
        certificate_pem: The matching certificate, embedded in the signature so a
            receiver can see which key was used.

    Raises:
        SigningFailed: There is no assertion to sign, the document will not parse,
            or xmlsec refused.
    """
    try:
        # SAFE_PARSER is the locked-down one from reader.py. This input is a
        # document we built a moment ago, but it's parsed with the same
        # parser anyway — "we made it" is the assumption that stops being
        # true after a refactor.
        root = etree.fromstring(response_xml.encode("utf-8"), parser=SAFE_PARSER)  # noqa: S320
    except etree.XMLSyntaxError as exc:
        raise SigningFailed(f"the response is not valid XML: {exc}") from exc

    # A direct child, not a descendant search. A document with an assertion
    # nested somewhere unexpected isn't one we built, and signing whatever
    # assertion turns up first is how signature wrapping happens.
    assertion = root.find(ASSERTION_TAG)
    if assertion is None:
        raise SigningFailed(
            "there is no assertion in this response to sign. A failure response has "
            "no assertion by design and must not be sent through here."
        )

    try:
        # The assertion on its own, not the whole response. add_sign signs the
        # parent of the first //saml:Issuer it finds, which in a response is
        # the response's own issuer — passing the whole document would sign
        # the wrapper and leave the assertion unprotected.
        signed_assertion = OneLogin_Saml2_Utils.add_sign(
            etree.tostring(assertion),
            private_key_pem,
            certificate_pem,
            # RSA-SHA256 and exclusive C14N with SHA-256 digests, explicit
            # rather than relying on defaults: SHA-1 is still the default in
            # some libraries and gets refused by newer versions on the
            # receiving side.
            sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
            digest_algorithm=OneLogin_Saml2_Constants.SHA256,
        )
    except Exception as exc:
        # Caught broadly: xmlsec surfaces failures as xmlsec.Error, lxml
        # errors, and occasionally ValueError. None of them are worth
        # distinguishing here since the document is unsigned either way and
        # must not be sent.
        raise SigningFailed(f"xmlsec refused to sign the assertion: {exc}") from exc

    # Put the signed assertion back where it came from. Safe because the
    # signature used exclusive canonicalisation, which omits
    # inherited-but-unused namespace declarations so a signed subtree can
    # move between documents without changing what was signed.
    replacement = etree.fromstring(signed_assertion, parser=SAFE_PARSER)  # noqa: S320
    root.replace(assertion, replacement)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8").decode("utf-8")


def sign_document(document_xml: str, *, private_key_pem: str, certificate_pem: str) -> str:
    """Sign a whole document at its root, and return it.

    For messages that carry no assertion — a LogoutResponse, and eventually a
    LogoutRequest. ``sign_assertion`` won't work for these: it signs the
    assertion inside a response and refuses a document with none, since
    signing the wrapper and leaving an assertion unprotected is the mistake
    that makes signature wrapping possible.

    Here there's nothing nested to protect — the document is one element with
    a status in it — so the root is the right thing to sign. The two
    functions stay separate rather than growing a parameter that picks which
    one to sign.

    Args:
        document_xml: A complete, final document. Nothing may change afterwards —
            the signature covers the canonicalised element.
        private_key_pem: The key to sign with.
        certificate_pem: The matching certificate, embedded so a receiver can see
            which key was used.

    Raises:
        SigningFailed: The document will not parse, or xmlsec refused.
    """
    try:
        # Same locked-down parser as everywhere else, for the same reason: "we
        # built it a moment ago" stops being true after a refactor.
        root = etree.fromstring(document_xml.encode("utf-8"), parser=SAFE_PARSER)  # noqa: S320
    except etree.XMLSyntaxError as exc:
        raise SigningFailed(f"the document is not valid XML: {exc}") from exc

    try:
        # add_sign signs the parent of the first //saml:Issuer it finds. In a
        # LogoutResponse that issuer is the document's own, so its parent is
        # the root, which is what we want here — and why sign_assertion
        # can't just be handed the whole document too.
        signed = OneLogin_Saml2_Utils.add_sign(
            etree.tostring(root),
            private_key_pem,
            certificate_pem,
            sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
            digest_algorithm=OneLogin_Saml2_Constants.SHA256,
        )
    except Exception as exc:
        # Caught broadly, same reason as sign_assertion: whatever xmlsec threw,
        # the document is unsigned and must not be sent.
        raise SigningFailed(f"xmlsec refused to sign the document: {exc}") from exc

    return signed.decode("utf-8") if isinstance(signed, bytes) else str(signed)
