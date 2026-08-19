"""Our side of the login: who we are, and how we ask someone to sign in.

No xmlsec here either. Building a login request is assembling a bit of XML and
compressing it, and our metadata document is the same. Both are plain strings, so
this runs and is tested anywhere.

We don't sign our login requests. That's normal and it's what most setups do: the
provider already knows which address to send the answer to, because that address
was agreed when the application was registered, and it won't send it anywhere
else. Signing them becomes worth doing in P5, when we're the one issuing logins
and we need a key anyway.
"""

from __future__ import annotations

import base64
import datetime as dt
import secrets
import zlib
from dataclasses import dataclass
from urllib.parse import urlencode
from xml.sax.saxutils import escape

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

    All three come from one base address, so there's a single thing to change when
    this moves from localhost to a real hostname. Getting these wrong is the most
    common setup mistake, and it fails in a confusing way: the provider signs
    someone in and then posts the answer somewhere that isn't us.
    """

    entity_id: str
    acs_url: str
    slo_url: str

    @classmethod
    def from_base_url(cls, base_url: str) -> ServiceProvider:
        root = base_url.rstrip("/")
        return cls(
            entity_id=f"{root}/saml/metadata",
            acs_url=f"{root}/saml/acs",
            slo_url=f"{root}/saml/sls",
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


def build_authn_request(
    *,
    sp: ServiceProvider,
    idp_sso_url: str,
    request_id: str,
    issued_at: dt.datetime,
    force_authn: bool = False,
) -> str:
    """Build the XML asking a provider to sign someone in.

    The id in here is the important part. The answer has to quote it back, and
    that's what proves the answer is for us rather than something someone posted at
    us out of the blue. It gets stored before the person is redirected, and looked
    up again when the answer arrives.
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

    Two things identify who to sign out. The NameID says which person, and the
    SessionIndex says which of their sessions — somebody signed in on a laptop and
    a phone has two, and leaving the index out asks the provider to end both.
    We send it, so signing out here signs out the one session that matches.

    The values are XML-escaped, unlike the ones in build_authn_request. That isn't
    inconsistency: those come from our own configuration, and these came from the
    provider and went through our database on the way here. An ampersand in a
    NameID would produce a document the provider can't parse, and a quote or an
    angle bracket would let it be steered.
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

    The provider is waiting to hear that we did it. Say so even when there was no
    session to end: from its point of view the person is signed out of this
    application either way, which is what it asked for.
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

    Raw deflate with no zlib header, which is what the spec asks for and what
    providers expect. Sending a normal zlib stream here produces a request the
    provider can't read, with an unhelpful error.
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


def redirect_binding_url(
    endpoint: str,
    *,
    saml_request: str | None = None,
    saml_response: str | None = None,
    relay_state: str | None = None,
) -> str:
    """Put a SAML message in a URL, the way the redirect binding wants it.

    Same shape as login_redirect_url, but for logout, where the message can be
    either a request or a response depending on who started it.

    Nothing here is signed. That is fine for a provider that doesn't insist on it,
    which authentik doesn't by default, and it's the same position we're already in
    with login requests. A provider that does insist needs a key of ours, which
    arrives in P5. See the note on the /saml/sls handler.
    """
    parameters: dict[str, str] = {}
    if saml_request is not None:
        parameters["SAMLRequest"] = deflate_and_encode(saml_request)
    if saml_response is not None:
        parameters["SAMLResponse"] = deflate_and_encode(saml_response)
    if relay_state:
        parameters["RelayState"] = relay_state

    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(parameters)}"


def is_safe_return_path(path: str) -> bool:
    """Whether it's safe to send someone here after they log in.

    Only paths within this site. Without this check, anyone could hand out a login
    link that sends people to their own site afterwards, and the link would look
    completely legitimate because it starts at a real login page.

    The double-slash case is the one people miss: "//evil.example" is a URL
    pointing at another host, not a path on this one.
    """
    if not path.startswith("/"):
        return False
    if path.startswith("//"):
        return False
    return "\\" not in path
