"""Signing the logins we issue.

The counterpart to reader.py, and like it, the only thing in this direction that
needs xmlsec — so it is the only part of the identity-provider side that cannot run
on Windows. Everything about *what* an assertion says lives in idp.py and stays
testable anywhere.

What gets signed, and why it is the assertion
---------------------------------------------

The signature goes over the assertion element, not the response wrapping it.

Both are legal, and providers differ. Signing only the response leaves the assertion
inside it unprotected against a receiver that pulls the assertion out and reads it on
its own — which is exactly the signature-wrapping shape reader.py refuses when we are
on the other side of this. Signing the assertion means the part carrying the claims is
the part that is protected, wherever it ends up.

Belt and braces would be signing both. We sign the assertion, which is what
authentik, Okta and Entra all do by default, and what every receiver expects.

How this actually gets the assertion signed
-------------------------------------------

python3-saml's ``add_sign`` finds the first ``//saml:Issuer`` in whatever it is
given, inserts the signature after it, and signs that issuer's parent. Handed a
whole response, the first issuer is the *response's* — so it would sign the
response and silently do the opposite of what this module is for.

So the assertion is pulled out, signed on its own, and put back. That is safe
because the signature uses exclusive canonicalisation, which is the form designed
for exactly this: it omits namespace declarations the subtree inherits but does not
use, so moving the element back into the response does not change what was signed.

Everything else in the document has to be final first. The signature covers the
canonicalised element, so one attribute added afterwards invalidates it — which is
why this takes a finished document and returns a finished document rather than
offering a builder.
"""

from __future__ import annotations

import logging

from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from iam.saml.reader import SAFE_PARSER

logger = logging.getLogger(__name__)

__all__ = ["SigningFailed", "sign_assertion"]

ASSERTION_TAG = f"{{{OneLogin_Saml2_Constants.NS_SAML}}}Assertion"


class SigningFailed(Exception):
    """The document could not be signed, and the message says why.

    Raised rather than returning an unsigned document, and that distinction
    matters: an unsigned assertion looks almost identical and is rejected by the
    receiver with a signature error, which sends whoever is debugging it to the
    wrong end of the connection entirely.
    """


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
        # S320 is about parsing untrusted XML with lxml. SAFE_PARSER is the locked
        # down one from reader.py, and this input is a document we built a moment
        # ago — but it is parsed with the same parser regardless, because "we made
        # it" is exactly the assumption that stops being true after a refactor.
        root = etree.fromstring(response_xml.encode("utf-8"), parser=SAFE_PARSER)  # noqa: S320
    except etree.XMLSyntaxError as exc:
        raise SigningFailed(f"the response is not valid XML: {exc}") from exc

    # Deliberately a direct child rather than a descendant search. A document with
    # an assertion nested somewhere unexpected is not one we built, and signing
    # whatever assertion turns up first is the mistake that makes signature
    # wrapping possible in the first place.
    assertion = root.find(ASSERTION_TAG)
    if assertion is None:
        raise SigningFailed(
            "there is no assertion in this response to sign. A failure response has "
            "no assertion by design and must not be sent through here."
        )

    try:
        # The assertion on its own, not the whole response. add_sign signs the
        # parent of the first //saml:Issuer it finds, and in a response that is the
        # response's own issuer — so passing the whole document would sign the
        # wrapper and leave the assertion inside it unprotected.
        signed_assertion = OneLogin_Saml2_Utils.add_sign(
            etree.tostring(assertion),
            private_key_pem,
            certificate_pem,
            # RSA-SHA256 and exclusive C14N with SHA-256 digests. SHA-1 is still
            # the default in several libraries and is refused by current versions
            # of the same libraries on the receiving side, so being explicit here
            # is what stops a login that works today failing after an upgrade
            # somewhere else.
            sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
            digest_algorithm=OneLogin_Saml2_Constants.SHA256,
        )
    except Exception as exc:
        # Caught broadly on purpose. xmlsec surfaces failures as xmlsec.Error,
        # lxml errors, and occasionally ValueError, and none of them are worth
        # distinguishing here: whatever it was, the document is unsigned and must
        # not be sent.
        raise SigningFailed(f"xmlsec refused to sign the assertion: {exc}") from exc

    # Put the signed assertion back where it came from. Safe because the signature
    # used exclusive canonicalisation, which omits inherited-but-unused namespace
    # declarations precisely so a signed subtree can move between documents.
    replacement = etree.fromstring(signed_assertion, parser=SAFE_PARSER)  # noqa: S320
    root.replace(assertion, replacement)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8").decode("utf-8")
