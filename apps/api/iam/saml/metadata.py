"""Reading a provider's metadata document.

This is how a provider gets registered. Their metadata says four things we need:
what they call themselves, where to send people to log in, where to send them to
log out, and the certificate every login from them has to be signed with. Typing
those in by hand is how you end up trusting the wrong key.

Why this parses XML with the standard library when reader.py uses lxml
-------------------------------------------------------------------

Different documents, different threat model, and the difference is the reason
the whole file exists.

A login response is attacker-supplied. It arrives on every sign-in, through the
browser of whoever is trying to get in, and it has to be verified
cryptographically. That one gets lxml, a locked-down parser, and xmlsec — and
because xmlsec doesn't install on Windows, it can only run in the container.

Metadata is different. An administrator pastes it in once, deliberately, while
setting up a provider. There's no signature to check, because trusting it is the
decision being made: whatever certificate this document names becomes the thing
every future login is checked against. Nothing is gained by cryptography here.

So this uses xml.etree from the standard library, which installs everywhere, and
that means registering a provider is covered by tests that run on a laptop and in
CI rather than only in a container. The two risks that come with it are dealt with
directly: a size cap, and a flat refusal to parse anything carrying a DOCTYPE,
which is what an entity expansion attack needs.

We do not fetch metadata URLs from the server. See ADR 0006.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from xml.etree import ElementTree

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

MAX_METADATA_BYTES = 512 * 1024
"""Refuse anything absurd before parsing. Real metadata is a few kilobytes."""

_PEM_BODY = re.compile(r"\s+")


class UnreadableMetadata(Exception):
    """The document isn't usable metadata, and we say which part is missing.

    "Could not register provider" sends somebody hunting. "The document has no
    sign-in address for the redirect binding" tells them what to fix.
    """


def certificate_body(pem_or_base64: str) -> str:
    """The certificate's base64, with the PEM markers and all whitespace removed."""
    without_markers = "\n".join(line for line in pem_or_base64.splitlines() if "-----" not in line)
    return _PEM_BODY.sub("", without_markers or pem_or_base64)


def certificate_fingerprint(pem_or_base64: str) -> str:
    """SHA-256 fingerprint of a certificate, in the form every other tool shows it.

    The same value `openssl x509 -fingerprint -sha256` prints, and the same one
    authentik and Okta show in their own consoles, so an administrator can compare
    the two and see they match. That's the whole job: making "is this the key I
    think it is" answerable without diffing two blocks of base64.

    It hashes the certificate itself, not the text around it. An earlier version of
    this took the first and last few characters of the PEM block, which meant every
    certificate on earth had the same fingerprint — they all start with
    "-----BEGIN CERTIFICATE-----". A test comparing two different certificates is
    what caught it, and that test is still there.
    """
    body = certificate_body(pem_or_base64)
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        # Not decodable, so there is no DER to hash and this won't match openssl.
        # Hashing the text keeps the one property that matters — it changes when
        # the certificate changes — rather than raising over a value we were only
        # ever going to display.
        der = body.encode("utf-8")

    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


@dataclass(frozen=True, slots=True)
class IdpMetadata:
    """What we take from a provider's metadata, ready to store.

    The field names match the identity_providers columns so registering is a copy
    rather than a translation.
    """

    entity_id: str
    sso_url: str
    signing_cert: str
    slo_url: str | None = None

    @property
    def certificate_fingerprint(self) -> str:
        """SHA-256 fingerprint of the signing certificate."""
        return certificate_fingerprint(self.signing_cert)


def _as_pem(base64_body: str) -> str:
    """Wrap a bare certificate from metadata in PEM markers.

    Metadata carries the base64 on its own, usually with the whitespace and line
    breaks of whatever generated it. python3-saml wants a PEM block, and it wants
    the body in 64-character lines, so this normalises both. Handing it the raw
    text works often enough to be misleading and then fails on one provider.
    """
    body = _PEM_BODY.sub("", base64_body)
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"


def _parse(xml: str) -> ElementTree.Element:
    raw = xml.strip()
    if not raw:
        raise UnreadableMetadata("the document is empty")

    if len(raw.encode("utf-8")) > MAX_METADATA_BYTES:
        raise UnreadableMetadata(f"the document is larger than {MAX_METADATA_BYTES} bytes")

    # Refused outright rather than parsed carefully. A DOCTYPE is what an entity
    # expansion attack needs, real metadata never has one, and "no DOCTYPE" is a
    # rule with no edge cases. Being clever with the parser instead would mean
    # relying on it staying clever.
    if "<!DOCTYPE" in raw.upper():
        raise UnreadableMetadata("the document declares a DOCTYPE, which we refuse to parse")

    try:
        return ElementTree.fromstring(raw)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise UnreadableMetadata(f"the document is not valid XML: {exc}") from exc


def _descriptor(root: ElementTree.Element) -> ElementTree.Element:
    """Find the part of the document describing the provider's login service.

    Metadata can describe several roles at once — the same document can say "here
    is how I act as an identity provider" and "here is how I act as an
    application". We want the first of those specifically. A document that only
    describes the second one is somebody's application metadata pasted in by
    mistake, which is a confusing thing to debug if it's reported as generic
    failure.
    """
    if root.tag == f"{{{NS['md']}}}IDPSSODescriptor":
        return root

    found = root.find("./md:IDPSSODescriptor", NS)
    if found is not None:
        return found

    # EntitiesDescriptor: several providers in one file, which federations hand
    # out. We take the first, and say so, rather than silently picking one.
    nested = root.find("./md:EntityDescriptor/md:IDPSSODescriptor", NS)
    if nested is not None:
        return nested

    if root.find("./md:SPSSODescriptor", NS) is not None:
        raise UnreadableMetadata(
            "this describes an application, not an identity provider. It looks like "
            "the metadata for the other side of the connection."
        )

    raise UnreadableMetadata("the document has no IDPSSODescriptor, so it isn't a login provider")


def _entity_id(root: ElementTree.Element, descriptor: ElementTree.Element) -> str:
    for candidate in (root, descriptor):
        entity_id = candidate.get("entityID")
        if entity_id and entity_id.strip():
            return entity_id.strip()

    nested = root.find("./md:EntityDescriptor", NS)
    if nested is not None:
        entity_id = nested.get("entityID")
        if entity_id and entity_id.strip():
            return entity_id.strip()

    raise UnreadableMetadata(
        "the document has no entityID, so there is no way to tell which provider "
        "a login came from"
    )


def _service_url(
    descriptor: ElementTree.Element, element_name: str, *, required: bool, label: str
) -> str | None:
    """The address for one service, preferring the redirect binding.

    Redirect first because that's what we send people over: the login request goes
    in a query string. A provider that only offers POST is unusual but valid, so
    it's taken rather than refused.
    """
    services = descriptor.findall(f"./md:{element_name}", NS)

    for binding in (REDIRECT_BINDING, POST_BINDING):
        for service in services:
            if service.get("Binding") == binding:
                location = (service.get("Location") or "").strip()
                if location:
                    return location

    # Anything else that at least has an address. Better than refusing over an
    # unrecognised binding string.
    for service in services:
        location = (service.get("Location") or "").strip()
        if location:
            return location

    if required:
        raise UnreadableMetadata(f"the document has no {label} address")
    return None


def _signing_cert(descriptor: ElementTree.Element) -> str:
    """The certificate logins from this provider must be signed with.

    This is the single most important value in the document. Everything about
    trusting a login reduces to "was it signed with the key matching this".

    A provider can list several certificates, and can mark them for signing, for
    encryption, or for both. We want a signing one. Taking the first certificate
    in the document regardless would eventually pick up an encryption-only key and
    fail every login with a signature error that points nowhere near the cause.
    """
    fallback: str | None = None

    for key_descriptor in descriptor.findall("./md:KeyDescriptor", NS):
        node = key_descriptor.find("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
        if node is None or not node.text or not node.text.strip():
            continue

        use = key_descriptor.get("use")
        if use == "signing":
            return _as_pem(node.text)
        if use is None and fallback is None:
            # No `use` means the key is good for anything, which includes signing.
            fallback = _as_pem(node.text)

    if fallback is not None:
        return fallback

    raise UnreadableMetadata(
        "the document has no signing certificate. Without one there is nothing to "
        "check a login against, so there would be no point registering this provider."
    )


def read_idp_metadata(xml: str) -> IdpMetadata:
    """Read a provider's metadata document.

    Raises:
        UnreadableMetadata: The document is missing something we can't do without,
            and the message says which.
    """
    root = _parse(xml)
    descriptor = _descriptor(root)

    return IdpMetadata(
        entity_id=_entity_id(root, descriptor),
        sso_url=_service_url(descriptor, "SingleSignOnService", required=True, label="sign-in")
        or "",
        slo_url=_service_url(descriptor, "SingleLogoutService", required=False, label="sign-out"),
        signing_cert=_signing_cert(descriptor),
    )
