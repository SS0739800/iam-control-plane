"""Being the identity provider: the documents we publish and the logins we issue.

P2 made us a service provider — we validate what somebody else signs. This is the
other direction, and it is the more dangerous one. Here we are the thing being
trusted, and an assertion we sign is accepted by every application that holds our
certificate. There is no second opinion.

Every value is escaped, and that is not routine
-----------------------------------------------

The XML on the SP side interpolates our own configuration into f-strings, which is
low risk because we chose those values. An assertion is different: it carries a
person's display name, their email, and the names of their groups, all of which came
from an HR system by way of a provider.

Somebody whose display name contains ``</saml:Attribute><saml:Attribute
Name="admin">`` would otherwise inject attributes into their own assertion, signed
by us, and every application downstream would believe them. So nothing reaches the
output without going through ``escape`` or ``quoteattr``, and there is a test that
tries exactly that name.

We have to produce what we ourselves demand
-------------------------------------------

The ten checks in checks.py are what we insist on as a service provider. The
assertion built here carries every field those checks look for — audience,
destination, recipient, both time windows, InResponseTo in two places — because a
provider that asks for more than it produces is a provider nobody can integrate
with, and because our own SP is the first thing that will read this.

No xmlsec in this module. It builds the document as text; signer.py adds the
signature, and that is the only part needing the container.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from xml.sax.saxutils import escape, quoteattr

SAML_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

# Not a password, despite the name — it is the URN naming how somebody signed in.
AUTHN_PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"  # noqa: S105
"""How the person authenticated, as far as the application is told.

Accurate rather than flattering: they signed in with a password at an upstream
provider, over TLS. Claiming a stronger context — multi-factor, say — would be
telling applications something we do not know.
"""

ASSERTION_LIFETIME = dt.timedelta(minutes=5)
"""How long the assertion is valid for.

Short, because it only has to survive one browser redirect. This is the window in
which a stolen assertion can be replayed against an application, so minutes rather
than hours — and our own SP additionally refuses one it has seen before.
"""

CLOCK_SKEW = dt.timedelta(minutes=1)
"""How far back NotBefore is set.

Clocks between here and an application are not perfectly aligned, and an assertion
that is not valid yet is rejected with a timing error nobody thinks to blame on
clocks. A minute costs nothing against a five minute lifetime.
"""


class SigningFailed(Exception):
    """The document could not be signed, and the message says why.

    Raised rather than returning an unsigned document, and that distinction
    matters: an unsigned assertion looks almost identical and is rejected by the
    receiver with a signature error, which sends whoever is debugging it to the
    wrong end of the connection entirely.

    Defined here rather than in signer.py, where it is raised, because signer.py
    needs xmlsec. The endpoint that catches this has to be importable on a laptop,
    and an `except` clause that cannot be imported is not much of a safety net.
    signer.py re-exports it, so `from iam.saml.signer import SigningFailed` still
    reads the way it should at the place that raises it.
    """


def new_id() -> str:
    """An XML id for a response or an assertion.

    Prefixed with an underscore because the SAML schema types these as xs:ID, which
    may not start with a digit — and a bare UUID starts with one about 60% of the
    time. That produces a document some parsers accept and others reject, which is
    the worst kind of bug to chase.
    """
    return f"_{uuid.uuid4().hex}"


def new_session_index() -> str:
    """Our name for this login, which the application quotes back when logging out."""
    return secrets.token_hex(16)


@dataclass(frozen=True, slots=True)
class Issuer:
    """Who we are, as an identity provider.

    Built from BASE_URL, so the metadata and every assertion agree by construction.
    Two places computing these separately is how an entity id ends up with a
    trailing slash in one document and not the other, which fails as an issuer
    mismatch.
    """

    base_url: str

    @classmethod
    def from_base_url(cls, base_url: str) -> Issuer:
        return cls(base_url=base_url.rstrip("/"))

    @property
    def entity_id(self) -> str:
        return f"{self.base_url}/idp/metadata"

    @property
    def sso_url(self) -> str:
        return f"{self.base_url}/idp/sso"

    @property
    def slo_url(self) -> str:
        return f"{self.base_url}/idp/slo"

    def metadata_xml(self, *, certificate_body: str) -> str:
        """The document an application is given when it starts trusting us.

        Says who we are, where to send people to sign in, and the certificate to
        check our signatures against. That certificate is the whole basis of the
        trust — everything else here is addressing.
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"\n'
            f"                     entityID={quoteattr(self.entity_id)}>\n"
            '  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"\n'
            "                       protocolSupportEnumeration="
            '"urn:oasis:names:tc:SAML:2.0:protocol">\n'
            '    <md:KeyDescriptor use="signing">\n'
            '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
            "        <ds:X509Data>\n"
            f"          <ds:X509Certificate>{escape(certificate_body)}"
            "</ds:X509Certificate>\n"
            "        </ds:X509Data>\n"
            "      </ds:KeyInfo>\n"
            "    </md:KeyDescriptor>\n"
            "    <md:SingleLogoutService\n"
            f'      Binding="{REDIRECT_BINDING}"\n'
            f"      Location={quoteattr(self.slo_url)}/>\n"
            f"    <md:NameIDFormat>{NAMEID_PERSISTENT}</md:NameIDFormat>\n"
            f"    <md:NameIDFormat>{NAMEID_EMAIL}</md:NameIDFormat>\n"
            "    <md:SingleSignOnService\n"
            f'      Binding="{REDIRECT_BINDING}"\n'
            f"      Location={quoteattr(self.sso_url)}/>\n"
            "    <md:SingleSignOnService\n"
            f'      Binding="{POST_BINDING}"\n'
            f"      Location={quoteattr(self.sso_url)}/>\n"
            "  </md:IDPSSODescriptor>\n"
            "</md:EntityDescriptor>\n"
        )


@dataclass(frozen=True, slots=True)
class LoginToIssue:
    """Everything one assertion needs to say.

    A single object rather than a dozen arguments, because the caller assembling
    this is the place where a wrong value does damage — passing the requester's
    entity id where the audience belongs, say — and named fields make that visible
    at the call site.
    """

    # ------------------------------------------------------------- the person
    name_id: str
    name_id_format: str = NAMEID_PERSISTENT
    attributes: Mapping[str, Sequence[str]] = field(default_factory=dict)

    # -------------------------------------------------------- the application
    audience: str = ""
    """The application's entity id. What its own audience check compares against."""

    acs_url: str = ""
    """Where the response is posted. Also the Recipient inside the assertion, which
    is a separate check in the spec and in checks.py."""

    in_response_to: str | None = None
    """The AuthnRequest id, when there was one. Absent for a login we started
    ourselves, which is legal and is what an application calls IdP-initiated."""

    # ----------------------------------------------------------------- timing
    issued_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.UTC))
    lifetime: dt.timedelta = ASSERTION_LIFETIME
    session_index: str = field(default_factory=new_session_index)

    @property
    def not_before(self) -> dt.datetime:
        return self.issued_at - CLOCK_SKEW

    @property
    def not_on_or_after(self) -> dt.datetime:
        return self.issued_at + self.lifetime


def _instant(moment: dt.datetime) -> str:
    """A timestamp in the format SAML wants.

    Always UTC with a Z, never an offset. Both are legal and some implementations
    only ever got the Z form right, so this is one of those places where following
    the spec exactly is less useful than following what everybody actually sends.
    """
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _attribute_statement(attributes: Mapping[str, Sequence[str]]) -> str:
    """The attributes, escaped.

    This is where somebody else's data enters a document we sign. Both the names
    and the values go through escaping, because a provider can be configured to
    send an attribute called anything at all.
    """
    if not attributes:
        return ""

    parts = ["    <saml:AttributeStatement>\n"]
    for name, values in attributes.items():
        parts.append(
            f"      <saml:Attribute Name={quoteattr(name)}\n"
            '                      NameFormat="urn:oasis:names:tc:SAML:2.0:'
            'attrname-format:basic">\n'
        )
        for value in values:
            parts.append(
                '        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance"\n'
                '                             xsi:type="xs:string">'
                f"{escape(str(value))}</saml:AttributeValue>\n"
            )
        parts.append("      </saml:Attribute>\n")
    parts.append("    </saml:AttributeStatement>\n")
    return "".join(parts)


def build_assertion(login: LoginToIssue, *, issuer: Issuer, assertion_id: str) -> str:
    """One assertion, unsigned.

    Carries every field checks.py looks for, because our own service provider is the
    first thing that will read this and a provider that demands more than it produces
    is one nobody can integrate with.
    """
    in_response_to = (
        f" InResponseTo={quoteattr(login.in_response_to)}" if login.in_response_to else ""
    )

    return (
        f'  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"\n'
        f"                  ID={quoteattr(assertion_id)}\n"
        f'                  Version="2.0"\n'
        f'                  IssueInstant="{_instant(login.issued_at)}">\n'
        f"    <saml:Issuer>{escape(issuer.entity_id)}</saml:Issuer>\n"
        "    <saml:Subject>\n"
        f"      <saml:NameID Format={quoteattr(login.name_id_format)}>"
        f"{escape(login.name_id)}</saml:NameID>\n"
        '      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">\n'
        "        <saml:SubjectConfirmationData"
        f"{in_response_to}\n"
        f'          NotOnOrAfter="{_instant(login.not_on_or_after)}"\n'
        f"          Recipient={quoteattr(login.acs_url)}/>\n"
        "      </saml:SubjectConfirmation>\n"
        "    </saml:Subject>\n"
        f'    <saml:Conditions NotBefore="{_instant(login.not_before)}"\n'
        f'                     NotOnOrAfter="{_instant(login.not_on_or_after)}">\n'
        "      <saml:AudienceRestriction>\n"
        f"        <saml:Audience>{escape(login.audience)}</saml:Audience>\n"
        "      </saml:AudienceRestriction>\n"
        "    </saml:Conditions>\n"
        f'    <saml:AuthnStatement AuthnInstant="{_instant(login.issued_at)}"\n'
        f"                         SessionIndex={quoteattr(login.session_index)}>\n"
        "      <saml:AuthnContext>\n"
        f"        <saml:AuthnContextClassRef>{AUTHN_PASSWORD_PROTECTED}"
        "</saml:AuthnContextClassRef>\n"
        "      </saml:AuthnContext>\n"
        "    </saml:AuthnStatement>\n"
        f"{_attribute_statement(login.attributes)}"
        "  </saml:Assertion>\n"
    )


def build_response(
    login: LoginToIssue,
    *,
    issuer: Issuer,
    response_id: str | None = None,
    assertion_id: str | None = None,
) -> str:
    """The whole response document, unsigned. signer.py signs it.

    Returned unsigned rather than signed here so that everything about *what* the
    document says is testable without xmlsec, and only the signature needs the
    container. It is also the honest split: this module decides content, that one
    proves authorship.
    """
    in_response_to = (
        f" InResponseTo={quoteattr(login.in_response_to)}" if login.in_response_to else ""
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"\n'
        '                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"\n'
        f"                ID={quoteattr(response_id or new_id())}\n"
        '                Version="2.0"\n'
        f'                IssueInstant="{_instant(login.issued_at)}"\n'
        f"                Destination={quoteattr(login.acs_url)}"
        f"{in_response_to}>\n"
        f"  <saml:Issuer>{escape(issuer.entity_id)}</saml:Issuer>\n"
        "  <samlp:Status>\n"
        f'    <samlp:StatusCode Value="{SAML_SUCCESS}"/>\n'
        "  </samlp:Status>\n"
        f"{build_assertion(login, issuer=issuer, assertion_id=assertion_id or new_id())}"
        "</samlp:Response>\n"
    )


def build_failure_response(
    *,
    issuer: Issuer,
    acs_url: str,
    in_response_to: str | None,
    status_code: str,
    message: str,
    issued_at: dt.datetime | None = None,
) -> str:
    """A response that says no, with no assertion in it.

    Worth having rather than returning an HTTP error. An application that sent us an
    AuthnRequest is waiting on a browser redirect, and a 403 page leaves the person
    stranded on our domain with no way back. A SAML failure lands them back at the
    application, which can then say something useful about why.
    """
    moment = issued_at or dt.datetime.now(dt.UTC)
    responding_to = f" InResponseTo={quoteattr(in_response_to)}" if in_response_to else ""

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"\n'
        '                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"\n'
        f"                ID={quoteattr(new_id())}\n"
        '                Version="2.0"\n'
        f'                IssueInstant="{_instant(moment)}"\n'
        f"                Destination={quoteattr(acs_url)}"
        f"{responding_to}>\n"
        f"  <saml:Issuer>{escape(issuer.entity_id)}</saml:Issuer>\n"
        "  <samlp:Status>\n"
        '    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">\n'
        f"      <samlp:StatusCode Value={quoteattr(status_code)}/>\n"
        "    </samlp:StatusCode>\n"
        f"    <samlp:StatusMessage>{escape(message)}</samlp:StatusMessage>\n"
        "  </samlp:Status>\n"
        "</samlp:Response>\n"
    )
