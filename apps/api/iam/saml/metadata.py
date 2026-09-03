"""Reading a provider's metadata document.

This is how a provider gets registered. Their metadata says four things we
need: what they call themselves, where to send people to log in, where to send
them to log out, and the certificate every login from them has to be signed
with. Typing those in by hand is how you end up trusting the wrong key.

This uses xml.etree from the standard library instead of the lxml + xmlsec
setup reader.py uses, because the threat model is different. A login response
is attacker-supplied and has to be verified cryptographically, so it needs
lxml, xmlsec, and the container xmlsec requires. Metadata is pasted in once by
an administrator setting up a provider; there's no signature to check, since
trusting it is the decision being made here. So there's nothing to gain from
xmlsec, and using the standard library instead means registering a provider is
covered by tests on a laptop and in CI, not just in the container.

The two risks that come with a laxer parser are handled directly: a size cap,
and a flat refusal to parse anything with a DOCTYPE (what an entity expansion
attack needs).

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

    Same value `openssl x509 -fingerprint -sha256` prints, and the same one
    authentik and Okta show in their consoles, so an administrator can compare
    the two without diffing two blocks of base64.

    Hashes the certificate itself, not the text around it. An earlier version
    hashed the first and last few characters of the PEM block, which gave
    every certificate the same fingerprint since they all start with
    "-----BEGIN CERTIFICATE-----". There's still a test comparing two
    different certificates that catches this.
    """
    body = certificate_body(pem_or_base64)
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        # Not decodable, so this won't match openssl, but hashing the raw text
        # still changes when the certificate changes, which is all we need
        # since this is only for display.
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

    Metadata carries the base64 on its own, with whatever whitespace and line
    breaks the generator used. python3-saml wants a PEM block with the body in
    64-character lines, so this normalises both.
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
    # expansion attack needs, and real metadata never has one.
    if "<!DOCTYPE" in raw.upper():
        raise UnreadableMetadata("the document declares a DOCTYPE, which we refuse to parse")

    try:
        return ElementTree.fromstring(raw)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise UnreadableMetadata(f"the document is not valid XML: {exc}") from exc


def _descriptor(root: ElementTree.Element) -> ElementTree.Element:
    """Find the part of the document describing the provider's login service.

    Metadata can describe several roles at once: the same document can say
    "here is how I act as an identity provider" and "here is how I act as an
    application". We want the first. A document that only describes the
    second is somebody's application metadata pasted in by mistake, so we say
    that plainly instead of just failing generically.
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
    descriptor: ElementTree.Element,
    element_name: str,
    *,
    required: bool,
    label: str,
    prefer: tuple[str, ...] = (REDIRECT_BINDING, POST_BINDING),
) -> str | None:
    """The address for one service, in order of binding preference.

    Redirect first by default, since that's what we send people over: a login
    request goes in a query string. A provider that only offers POST is
    unusual but valid, so it's taken rather than refused.

    The preference is a parameter because it flips for one case: an
    application's assertion consumer must be the POST address, since an
    assertion is too long for a query string.
    """
    services = descriptor.findall(f"./md:{element_name}", NS)

    for binding in prefer:
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

    The single most important value in the document: trusting a login comes
    down to "was it signed with the key matching this".

    A provider can list several certificates, marked for signing, encryption,
    or both. We want a signing one. Taking the first certificate regardless
    would eventually pick up an encryption-only key and fail every login with
    a confusing signature error.
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


@dataclass(frozen=True, slots=True)
class SpMetadata:
    """What we take from an application's metadata, ready to store.

    The mirror of IdpMetadata; field names match the applications columns so
    registering is a copy rather than a translation.
    """

    entity_id: str
    acs_url: str
    slo_url: str | None = None
    signing_cert: str | None = None
    """The application's own certificate, when it publishes one.

    Optional, unlike IdpMetadata's. A provider's certificate is compulsory
    since checking a login's signature depends on it. An application's is
    only needed if it signs the requests it sends us, and most don't, so a
    missing one is normal here.
    """

    want_assertions_signed: bool = True
    """Whether the application asks for the assertion itself to be signed.

    Read for completeness. We sign the assertion either way, since signing
    only the response wrapper would leave the claims swappable (see
    signer.py).
    """


def _sp_descriptor(root: ElementTree.Element) -> ElementTree.Element:
    """Find the part of the document describing the application.

    The mirror of _descriptor: a document that only describes an identity
    provider says so rather than failing generically, since pasting in the
    wrong side's metadata is an easy mistake to make.
    """
    if root.tag == f"{{{NS['md']}}}SPSSODescriptor":
        return root

    found = root.find("./md:SPSSODescriptor", NS)
    if found is not None:
        return found

    nested = root.find("./md:EntityDescriptor/md:SPSSODescriptor", NS)
    if nested is not None:
        return nested

    if root.find("./md:IDPSSODescriptor", NS) is not None:
        raise UnreadableMetadata(
            "this describes an identity provider, not an application. It looks like "
            "the metadata for the other side of the connection — register it under "
            "identity providers instead."
        )

    raise UnreadableMetadata(
        "the document has no SPSSODescriptor, so it isn't an application that can " "receive logins"
    )


def read_sp_metadata(xml: str) -> SpMetadata:
    """Read an application's metadata document.

    Same rules as read_idp_metadata: pasted in, never fetched (ADR 0006), parsed
    with the standard library, and refused outright if it carries a DOCTYPE.

    Raises:
        UnreadableMetadata: The document is missing something we can't do without,
            and the message says which.
    """
    root = _parse(xml)
    descriptor = _sp_descriptor(root)

    acs_url = _service_url(
        descriptor,
        "AssertionConsumerService",
        required=True,
        label="assertion consumer",
        # POST, not redirect: an assertion is delivered as a form POST since
        # it's too long for a query string, so a redirect-binding address here
        # wouldn't be usable even if the application publishes one.
        prefer=(POST_BINDING, REDIRECT_BINDING),
    )

    return SpMetadata(
        entity_id=_entity_id(root, descriptor),
        acs_url=acs_url or "",
        slo_url=_service_url(descriptor, "SingleLogoutService", required=False, label="sign-out"),
        # Optional here, unlike the provider side, so the strict reader is not used.
        signing_cert=_optional_signing_cert(descriptor),
        want_assertions_signed=(
            (descriptor.get("WantAssertionsSigned") or "").strip().lower() != "false"
        ),
    )


def _optional_signing_cert(descriptor: ElementTree.Element) -> str | None:
    """An application's signing certificate, if it publishes one.

    Returns None instead of raising, unlike _signing_cert. Most applications
    never sign anything they send us, so refusing metadata without a
    certificate would refuse the common case.
    """
    try:
        return _signing_cert(descriptor)
    except UnreadableMetadata:
        return None
