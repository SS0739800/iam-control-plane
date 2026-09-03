"""Our side of the login: who we are, and how we ask someone to sign in.

No xmlsec here either. Building a login request is assembling a bit of XML
and compressing it, and our metadata document is the same — both plain
strings, so this runs and is tested anywhere.

We don't sign our login requests. That's normal, and what most setups do:
the provider already knows which address to send the answer to (agreed at
registration) and won't send it anywhere else. Signing becomes worth doing
in P5, when we're the one issuing logins and need a key anyway.
"""

from __future__ import annotations

import base64
import datetime as dt
import secrets
import zlib
from dataclasses import dataclass
from urllib.parse import urlencode
from xml.sax.saxutils import escape

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RELAY_STATE_BYTES = 32
"""Length of the random token we send with a login request.

It has to be unguessable, because finding a valid one is enough to submit an
answer to a request you didn't make."""

REQUEST_TTL = dt.timedelta(minutes=10)
"""How long we'll wait for someone to finish logging in.

Long enough to type a password and deal with a second factor, short enough that an
abandoned request doesn't sit around being answerable."""


def new_relay_state() -> str:
    """A random token tying an answer back to the request we sent."""
    return secrets.token_urlsafe(RELAY_STATE_BYTES)


def new_request_id() -> str:
    """A fresh id for a login request.

    Starts with a letter because the XML id type doesn't allow a leading digit,
    and some providers reject the document outright if it does.
    """
    return f"id-{secrets.token_hex(16)}"


@dataclass(frozen=True, slots=True)
class ServiceProvider:
    """Who we are, from a provider's point of view.

    All three come from one base address, so there's a single thing to change
    when this moves from localhost to a real hostname. Getting these wrong is
    a common setup mistake and fails confusingly: the provider signs someone
    in and posts the answer somewhere that isn't us.
    """

    entity_id: str
    acs_url: str
    slo_url: str

    signing_certificate: str | None = None
    """Our certificate, base64 with no header, or None when none is configured.

    Published so a provider can verify the logout requests we sign. A
    signature nobody can check is worse than none: it looks like security
    and isn't.
    """

    @classmethod
    def from_base_url(
        cls, base_url: str, signing_certificate: str | None = None
    ) -> ServiceProvider:
        root = base_url.rstrip("/")
        return cls(
            entity_id=f"{root}/saml/metadata",
            acs_url=f"{root}/saml/acs",
            slo_url=f"{root}/saml/sls",
            signing_certificate=signing_certificate,
        )

    def metadata_xml(self) -> str:
        """The document you hand a provider when registering this application.

        Says three things: what we call ourselves, where to send the answer, and
        that we want the assertion itself signed rather than just the envelope.
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"\n'
            f'                     entityID="{self.entity_id}">\n'
            '  <md:SPSSODescriptor AuthnRequestsSigned="false"\n'
            '                      WantAssertionsSigned="true"\n'
            "                      protocolSupportEnumeration="
            '"urn:oasis:names:tc:SAML:2.0:protocol">\n'
            f"{self._key_descriptor()}"
            "    <md:SingleLogoutService\n"
            '      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"\n'
            f'      Location="{self.slo_url}"/>\n'
            "    <md:NameIDFormat>"
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
            "</md:NameIDFormat>\n"
            "    <md:AssertionConsumerService\n"
            '      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"\n'
            f'      Location="{self.acs_url}"\n'
            '      index="0" isDefault="true"/>\n'
            "  </md:SPSSODescriptor>\n"
            "</md:EntityDescriptor>\n"
        )

    def _key_descriptor(self) -> str:
        """Our signing certificate, or nothing at all.

        Omitted rather than left empty when no key is configured. An empty
        KeyDescriptor gets rejected outright by some providers and silently
        fails verification on others — both worse than omitting it, which
        just means "this application doesn't sign".
        """
        if not self.signing_certificate:
            return ""
        return (
            '    <md:KeyDescriptor use="signing">\n'
            '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
            "        <ds:X509Data>\n"
            f"          <ds:X509Certificate>{self.signing_certificate}"
            f"</ds:X509Certificate>\n"
            "        </ds:X509Data>\n"
            "      </ds:KeyInfo>\n"
            "    </md:KeyDescriptor>\n"
        )


def build_authn_request(
    *,
    sp: ServiceProvider,
    idp_sso_url: str,
    request_id: str,
    issued_at: dt.datetime,
    force_authn: bool = False,
) -> str:
    """Build the XML asking a provider to sign someone in.

    The id is the important part. The answer has to quote it back, which is
    what proves the answer is for us rather than something posted at us out
    of the blue. It's stored before the redirect and looked up again when the
    answer arrives.
    """
    stamp = issued_at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    force = ' ForceAuthn="true"' if force_authn else ""

    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        ' Version="2.0"'
        f' IssueInstant="{stamp}"'
        ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
        f' AssertionConsumerServiceURL="{sp.acs_url}"'
        f' Destination="{idp_sso_url}"'
        f"{force}>"
        f"<saml:Issuer>{sp.entity_id}</saml:Issuer>"
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"'
        ' AllowCreate="true"/>'
        "</samlp:AuthnRequest>"
    )


def build_logout_request(
    *,
    sp: ServiceProvider,
    idp_slo_url: str,
    request_id: str,
    name_id: str,
    issued_at: dt.datetime,
    name_id_format: str | None = None,
    session_index: str | None = None,
) -> str:
    """Build the XML asking a provider to sign someone out.

    Two things identify who to sign out: the NameID says which person, and
    the SessionIndex says which of their sessions (somebody signed in on a
    laptop and a phone has two). Leaving the index out asks the provider to
    end both; we send it so only the matching session ends.

    The values here are XML-escaped, unlike build_authn_request's. That's not
    inconsistency: those come from our own configuration, these came from the
    provider through our database. An ampersand in a NameID would break
    parsing, and a quote or angle bracket unescaped would let the value steer
    the document.
    """
    stamp = issued_at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    name_format = f' Format="{name_id_format}"' if name_id_format else ""
    index = (
        f"<samlp:SessionIndex>{escape(session_index)}</samlp:SessionIndex>" if session_index else ""
    )

    return (
        '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        ' Version="2.0"'
        f' IssueInstant="{stamp}"'
        f' Destination="{escape(idp_slo_url)}">'
        f"<saml:Issuer>{escape(sp.entity_id)}</saml:Issuer>"
        f"<saml:NameID{name_format}>{escape(name_id)}</saml:NameID>"
        f"{index}"
        "</samlp:LogoutRequest>"
    )


def build_logout_response(
    *,
    sp: ServiceProvider,
    idp_slo_url: str,
    response_id: str,
    in_response_to: str,
    issued_at: dt.datetime,
    success: bool = True,
) -> str:
    """Build the answer to a provider's request that we sign somebody out.

    Says success even with no session to end: from the provider's point of
    view the person is signed out of this application either way, which is
    what it asked for.
    """
    stamp = issued_at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    status = (
        "urn:oasis:names:tc:SAML:2.0:status:Success"
        if success
        else "urn:oasis:names:tc:SAML:2.0:status:Requester"
    )

    return (
        '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{response_id}"'
        ' Version="2.0"'
        f' IssueInstant="{stamp}"'
        f' Destination="{escape(idp_slo_url)}"'
        f' InResponseTo="{escape(in_response_to)}">'
        f"<saml:Issuer>{escape(sp.entity_id)}</saml:Issuer>"
        f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>'
        "</samlp:LogoutResponse>"
    )


def deflate_and_encode(xml: str) -> str:
    """Compress and base64 the request, the way the redirect binding wants it.

    Raw deflate with no zlib header, per spec. A normal zlib stream here
    produces a request the provider can't read, with an unhelpful error.
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    deflated = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    return base64.b64encode(deflated).decode("ascii")


def login_redirect_url(*, idp_sso_url: str, authn_request_xml: str, relay_state: str) -> str:
    """The URL to send someone to so they can log in.

    Everything travels in the query string, which is the redirect binding. There's
    no signature on it, so the provider is trusting that the request came from an
    application it knows, which it checks by looking at the issuer.
    """
    query = urlencode(
        {
            "SAMLRequest": deflate_and_encode(authn_request_xml),
            "RelayState": relay_state,
        }
    )
    separator = "&" if "?" in idp_sso_url else "?"
    return f"{idp_sso_url}{separator}{query}"


RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
"""The signature algorithm we use for the redirect binding.

Named in the query string as SigAlg, so the provider knows what to verify with.
"""


def redirect_binding_url(
    endpoint: str,
    *,
    saml_request: str | None = None,
    saml_response: str | None = None,
    relay_state: str | None = None,
    private_key_pem: str | None = None,
) -> str:
    """Put a SAML message in a URL, the way the redirect binding wants it.

    Same shape as login_redirect_url, but for logout, where the message can
    be either a request or a response depending on who started it.

    Signed when a key is given, and that's effectively required now: Okta
    refuses an unsigned LogoutRequest outright, so single logout used to do
    nothing — our session ended, theirs didn't, and the next login walked
    straight back in without a password, the opposite of what pressing sign
    out is supposed to do.

    This signs the query string, not the document. The rule is exact: build
    ``SAMLRequest=…&RelayState=…&SigAlg=…`` in that order, each value
    URL-encoded, sign those bytes, and append ``Signature=``. Not the decoded
    XML, not a different parameter order, not the string after the provider
    re-encodes it — get any of that wrong and the signature just fails with
    "invalid signature" and no clue why.

    RelayState is included only when we send one: the octet string signed has
    to match what's actually on the wire, and an empty parameter in the
    signature that's absent from the URL breaks it just as much as a real one
    that's missing.
    """
    parameters: dict[str, str] = {}
    if saml_request is not None:
        parameters["SAMLRequest"] = deflate_and_encode(saml_request)
    if saml_response is not None:
        parameters["SAMLResponse"] = deflate_and_encode(saml_response)
    if relay_state:
        parameters["RelayState"] = relay_state

    if private_key_pem is not None:
        parameters["SigAlg"] = RSA_SHA256
        # urlencode with the dict in insertion order gives exactly the octet
        # string the spec asks to be signed, which is also exactly what goes
        # in the URL. Building the two separately is how they'd drift apart.
        signed_part = urlencode(parameters)
        signature = urlencode({"Signature": _sign_query(signed_part, private_key_pem)})
        joiner = "&" if "?" in endpoint else "?"
        return f"{endpoint}{joiner}{signed_part}&{signature}"

    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(parameters)}"


def _sign_query(octets: str, private_key_pem: str) -> str:
    """Sign the redirect binding's query string, base64 for putting back in a URL.

    Uses cryptography instead of xmlsec: there's no XML here, and xmlsec only
    installs in the container, so this is the one part of SAML signing that
    can be tested on any machine.
    """
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("the SAML signing key must be RSA for the redirect binding")

    signature = key.sign(octets.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def is_safe_return_path(path: str) -> bool:
    """Whether it's safe to send someone here after they log in.

    Only paths within this site. Without this check, anyone could hand out a
    login link that redirects to their own site afterward, and it would look
    like a completely legitimate link since it starts at a real login page.

    The double-slash case is the one people miss: "//evil.example" is a URL
    pointing at another host, not a path on this one.
    """
    if not path.startswith("/"):
        return False
    if path.startswith("//"):
        return False
    return "\\" not in path
