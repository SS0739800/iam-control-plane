"""Reading claims from the three providers this is meant to work with.

The point of these is that adding a provider should be a data change, not a code
change. Each test below is one provider's real attribute shape, and the same
``read_claims`` handles all of them with no branching.

They are also the cheapest possible insurance against the failure that is most
annoying to diagnose in this area: a login that succeeds and produces a person with
a blank name, or one refused with "the login carries no email address or username"
while the assertion visibly contains one. Both come from a claim name that is
almost right.

No database and no xmlsec, so these run anywhere.
"""

from __future__ import annotations

import datetime as dt

import pytest

from iam.saml.checks import SAML_SUCCESS, AssertionFacts
from iam.saml.provisioning import UnusableAssertion, read_claims

NOW = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)


def facts(attributes: dict[str, list[str]], *, name_id: str = "a-stable-id") -> AssertionFacts:
    """A verified login carrying these attributes. Only the claims matter here."""
    return AssertionFacts(
        assertion_id="id-assertion",
        issuer="https://idp.test",
        status_code=SAML_SUCCESS,
        audiences=("http://localhost:8080/saml/metadata",),
        destination="http://localhost:8080/saml/acs",
        in_response_to="id-request",
        not_before=NOW - dt.timedelta(minutes=1),
        not_on_or_after=NOW + dt.timedelta(minutes=5),
        subject_not_on_or_after=NOW + dt.timedelta(minutes=5),
        subject_recipient="http://localhost:8080/saml/acs",
        subject_in_response_to="id-request",
        name_id=name_id,
        name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        session_index="a-session",
        attributes=attributes,
        signature_verified=True,
        assertion_was_signed=True,
    )


# ------------------------------------------------------------------- authentik


def test_authentik() -> None:
    """What we actually receive today, and the only one verified against a real
    provider rather than its documentation."""
    claims = read_claims(
        facts(
            {
                "http://schemas.goauthentik.io/2021/02/saml/username": ["ada.bergman"],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                    "ada@demo.local"
                ],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Ada"],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Bergman"],
            }
        )
    )

    assert claims.user_name == "ada.bergman"
    assert claims.email == "ada@demo.local"
    assert claims.display_name == "Ada Bergman"


# ------------------------------------------------------------------------ Okta


def test_okta() -> None:
    """Okta's SAML app templates use short, plain attribute names."""
    claims = read_claims(
        facts(
            {
                "login": ["ada.bergman@demo.local"],
                "email": ["ada.bergman@demo.local"],
                "firstName": ["Ada"],
                "lastName": ["Bergman"],
            },
            name_id="00u1a2b3c4d5e6f7g8h9",
        )
    )

    assert claims.user_name == "ada.bergman@demo.local"
    assert claims.email == "ada.bergman@demo.local"
    assert claims.display_name == "Ada Bergman"
    # No objectidentifier and no authentik uid, so the NameID stands in — which is
    # right, because Okta's is its own stable id for the person.
    assert claims.external_id == "00u1a2b3c4d5e6f7g8h9"


def test_okta_with_only_an_email() -> None:
    """A minimal Okta app sends the email and nothing else.

    Worth covering because it is what somebody gets when they click through the
    setup without adding attribute statements, and it should still produce a usable
    person rather than a refusal.
    """
    claims = read_claims(facts({"email": ["ada@demo.local"]}))

    assert claims.user_name == "ada@demo.local"
    assert claims.email == "ada@demo.local"
    assert claims.display_name == "ada@demo.local"


# ------------------------------------------------------------------- Entra ID


def test_entra_id() -> None:
    """Entra sends long URN claim names, and its own two Microsoft-specific ones."""
    claims = read_claims(
        facts(
            {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": [
                    "ada.bergman@demo.onmicrosoft.com"
                ],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                    "ada.bergman@demo.local"
                ],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Ada"],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Bergman"],
                "http://schemas.microsoft.com/identity/claims/displayname": ["Ada Bergman"],
                "http://schemas.microsoft.com/identity/claims/objectidentifier": [
                    "8f4c1e2a-0000-4a1b-9c3d-5e6f7a8b9c0d"
                ],
                "http://schemas.microsoft.com/identity/claims/tenantid": ["a-tenant"],
            }
        )
    )

    assert claims.user_name == "ada.bergman@demo.onmicrosoft.com"
    assert claims.email == "ada.bergman@demo.local"
    assert claims.display_name == "Ada Bergman"
    # The Entra object id, not the NameID. It is stable across a rename, which is
    # the whole reason to prefer it.
    assert claims.external_id == "8f4c1e2a-0000-4a1b-9c3d-5e6f7a8b9c0d"


def test_entra_prefers_upn_over_the_ambiguous_name_claim() -> None:
    """Entra's /claims/name usually holds the sign-in name and sometimes does not.

    So the UPN wins for the username, and /claims/name is only ever trusted for a
    display name. Getting this the wrong way round produces people whose userName is
    their full name, which then collides with the next person of the same name.
    """
    claims = read_claims(
        facts(
            {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": ["ada@demo.local"],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": ["Ada Bergman"],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                    "ada@demo.local"
                ],
            }
        )
    )

    assert claims.user_name == "ada@demo.local"
    assert claims.display_name == "Ada Bergman"


# --------------------------------------------------- names typed by a human


@pytest.mark.parametrize(
    "spelling",
    ["firstName", "FirstName", "firstname", "FIRSTNAME"],
)
def test_the_casing_of_a_claim_name_does_not_matter(spelling: str) -> None:
    """Provider consoles let somebody type the attribute name, so the same claim
    arrives differently cased from different tenants.

    An exact lookup finds none of these unless every casing is listed, and the
    failure is quiet: a login that works and produces a person with no first name.
    """
    claims = read_claims(facts({"email": ["ada@demo.local"], spelling: ["Ada"]}))

    assert claims.given_name == "Ada"


def test_a_differently_cased_username_claim_is_still_found() -> None:
    """The loud version of the same bug: refused for having no username, while the
    assertion plainly contains one."""
    claims = read_claims(facts({"UserName": ["ada.bergman"], "Email": ["ada@demo.local"]}))

    assert claims.user_name == "ada.bergman"
    assert claims.email == "ada@demo.local"


# ------------------------------------------------------- nothing usable at all


def test_a_login_with_no_identifier_is_refused() -> None:
    """Almost always a provider nobody told which attributes to send. The message
    says so, because that is the actual fix."""
    with pytest.raises(UnusableAssertion, match="no email address or username"):
        read_claims(facts({"http://schemas.microsoft.com/identity/claims/tenantid": ["a-tenant"]}))


def test_a_username_that_is_not_an_email_does_not_become_one() -> None:
    """authentik sends a bare username. Copying that into the email column would put
    nonsense in it, so the login is refused instead."""
    with pytest.raises(UnusableAssertion):
        read_claims(facts({"userName": ["ada.bergman"]}))
