"""Being the identity provider: the documents we publish and the logins we issue.

This is the other direction from being a service provider (see checks.py): here
we're the thing being trusted, and an assertion we sign is accepted by every
application holding our certificate. There's no second opinion.

Every attribute value is escaped through ``escape`` or ``quoteattr`` before it
reaches the output. An assertion carries a person's display name, email, and
group names, all sourced from an HR system by way of a provider. Without
escaping, a display name containing ``</saml:Attribute><saml:Attribute
Name="admin">`` could inject extra attributes into an assertion we sign
ourselves. There's a test that tries exactly that name.

The assertion built here carries every field checks.py looks for (audience,
destination, recipient, both time windows, InResponseTo in two places), since
our own SP is the first thing that reads it and has to accept it.

No xmlsec in this module. It builds the document as text; signer.py adds the
signature and is the only part that needs the xmlsec container.
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

They signed in with a password at an upstream provider, over TLS. Claiming a
stronger context (multi-factor, say) would tell applications something we
don't actually know.
"""

ASSERTION_LIFETIME = dt.timedelta(minutes=5)
"""How long the assertion is valid for.

Short, since it only has to survive one browser redirect. This is also the
window in which a stolen assertion could be replayed, so minutes rather than
hours; our own SP additionally refuses one it has seen before.
"""

CLOCK_SKEW = dt.timedelta(minutes=1)
"""How far back NotBefore is set.

Clocks between here and an application aren't perfectly aligned. Without this,
an assertion that isn't valid yet gets rejected with a timing error that's easy
to misdiagnose. A minute costs nothing against a five minute lifetime.
"""


class SigningFailed(Exception):
    """The document could not be signed, and the message says why.

    Raised instead of returning an unsigned document, since an unsigned
    assertion looks almost identical and would be rejected downstream with a
    confusing signature error.

    Defined here rather than in signer.py, where it's raised, because signer.py
    needs xmlsec and the endpoint that catches this has to import on a laptop
    without it. signer.py re-exports it, so `from iam.saml.signer import
    SigningFailed` still works at the place that raises it.
    """


def new_id() -> str:
    """An XML id for a response or an assertion.

    Prefixed with an underscore because the SAML schema types these as xs:ID,
    which can't start with a digit, and a bare UUID starts with one about 60%
    of the time. Some parsers accept a digit-led id anyway and others reject
    it, so this avoids the issue entirely.
    """
    return f"_{uuid.uuid4().hex}"


def new_session_index() -> str:
    """Our name for this login, which the application quotes back when logging out."""
    return secrets.token_hex(16)


@dataclass(frozen=True, slots=True)
class Issuer:
    """Who we are, as an identity provider.

    Built from BASE_URL, so the metadata and every assertion agree by
    construction. Computing these separately in two places is how an entity id
    ends up with a trailing slash in one document and not the other, which
    then fails as an issuer mismatch.
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

        Says who we are, where to send people to sign in, and the certificate
        to check our signatures against. The certificate is the whole basis of
        the trust; everything else here is just addressing.
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

    A single object rather than a dozen positional arguments, so a mistake like
    passing the requester's entity id where the audience belongs is visible as
    a named field at the call site.
    """

    # ------------------------------------------------------------- the person
    name_id: str
    name_id_format: str = NAMEID_PERSISTENT
    attributes: Mapping[str, Sequence[str]] = field(default_factory=dict)

    # -------------------------------------------------------- the application
    audience: str = ""
    """The application's entity id. What its own audience check compares against."""

    acs_url: str = ""
    """Where the response is posted. Also the Recipient inside the assertion,
    which is a separate check in the spec and in checks.py."""

    in_response_to: str | None = None
    """The AuthnRequest id, when there was one. Absent for a login we started
    ourselves, which is legal (an application calls this IdP-initiated)."""

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

    Always UTC with a Z, never an offset. Both are legal, but some
    implementations only handle the Z form correctly.
    """
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _attribute_statement(attributes: Mapping[str, Sequence[str]]) -> str:
    """The attributes, escaped.

    This is where somebody else's data enters a document we sign. Both names
    and values go through escaping, since a provider can be configured to send
    an attribute called anything at all.
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

    Carries every field checks.py looks for, since our own service provider is
    the first thing that reads it.
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

    Returned unsigned so everything about what the document says is testable
    without xmlsec; only the signature step needs it. This module decides
    content, signer.py proves authorship.
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

    Used instead of an HTTP error because the application is waiting on a
    browser redirect; a 403 page would strand the person on our domain with no
    way back. This sends them back to the application, which can say something
    useful about why.
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


def build_logout_response(
    *,
    issuer: Issuer,
    destination: str,
    in_response_to: str,
    issued_at: dt.datetime,
    success: bool = True,
) -> str:
    """Confirm to an application that we signed somebody out.

    Says success even when there was no session to end: the application wanted
    the person signed out, and if they already were, that's the state it
    wanted. A failure here would invite retries that have nothing left to do.

    ``success=False`` is for a genuine failure, like a request we can't read or
    one naming a session belonging to somebody else.
    """
    status = (
        "urn:oasis:names:tc:SAML:2.0:status:Success"
        if success
        else "urn:oasis:names:tc:SAML:2.0:status:Requester"
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"\n'
        '                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"\n'
        f"                      ID={quoteattr(new_id())}\n"
        '                      Version="2.0"\n'
        f'                      IssueInstant="{_instant(issued_at)}"\n'
        f"                      Destination={quoteattr(destination)}\n"
        f"                      InResponseTo={quoteattr(in_response_to)}>\n"
        f"  <saml:Issuer>{escape(issuer.entity_id)}</saml:Issuer>\n"
        "  <samlp:Status>\n"
        f'    <samlp:StatusCode Value="{status}"/>\n'
        "  </samlp:Status>\n"
        "</samlp:LogoutResponse>\n"
    )
