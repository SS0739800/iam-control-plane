"""Tests for turning a verified login into a person.

Two halves. Reading the claims is pure and runs anywhere. Matching against the
directory needs Postgres, so those are marked integration and skip without it.

The claim-reading tests deliberately use the real attribute names each provider
sends, ugly URIs and all. Made-up names would pass while the actual authentik
attribute went unread.

No xmlsec here, so the first half runs on Windows.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import IdentitySource, PlatformRole
from iam.models.user import User
from iam.saml.checks import AssertionFacts
from iam.saml.provisioning import (
    IdentityClaims,
    UnusableAssertion,
    build_user,
    find_user,
    provision_user,
    read_claims,
    refresh_user,
)

AUTHENTIK_ATTRIBUTES = {
    "http://schemas.goauthentik.io/2021/02/saml/username": ["ada.bergman"],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
        "ada.bergman@demo.local"
    ],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Ada"],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Bergman"],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": ["Ada Bergman"],
}

OKTA_ATTRIBUTES = {
    "email": ["ada.bergman@demo.local"],
    "firstName": ["Ada"],
    "lastName": ["Bergman"],
}

ENTRA_ATTRIBUTES = {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
        "ada.bergman@demo.local"
    ],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Ada"],
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Bergman"],
    "http://schemas.microsoft.com/identity/claims/displayname": ["Ada Bergman"],
    "http://schemas.microsoft.com/identity/claims/objectidentifier": ["9f1c-entra-oid"],
}


def facts(**overrides: object) -> AssertionFacts:
    defaults: dict[str, object] = {
        "assertion_id": "id-assertion-abc",
        "issuer": "https://authentik.demo.local",
        "status_code": "urn:oasis:names:tc:SAML:2.0:status:Success",
        "name_id": "persistent-pseudonym-0001",
        "attributes": dict(AUTHENTIK_ATTRIBUTES),
    }
    defaults.update(overrides)
    return AssertionFacts(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------ reading claims


def test_reads_the_claims_authentik_actually_sends() -> None:
    claims = read_claims(facts())

    assert claims.user_name == "ada.bergman"
    assert claims.email == "ada.bergman@demo.local"
    assert claims.given_name == "Ada"
    assert claims.family_name == "Bergman"
    assert claims.display_name == "Ada Bergman"


def test_reads_the_claims_okta_actually_sends() -> None:
    """Okta sends plain names and no separate username."""
    claims = read_claims(facts(attributes=dict(OKTA_ATTRIBUTES)))

    assert claims.user_name == "ada.bergman@demo.local"
    assert claims.email == "ada.bergman@demo.local"
    assert claims.display_name == "Ada Bergman"


def test_reads_the_claims_entra_actually_sends() -> None:
    claims = read_claims(facts(attributes=dict(ENTRA_ATTRIBUTES)))

    assert claims.email == "ada.bergman@demo.local"
    assert claims.display_name == "Ada Bergman"
    assert claims.external_id == "9f1c-entra-oid"


def test_the_name_id_is_the_external_id_when_no_claim_carries_one() -> None:
    """The persistent NameID is the provider's stable handle for someone, which is
    what we want to match them on next time."""
    assert read_claims(facts()).external_id == "persistent-pseudonym-0001"


def test_an_explicit_external_id_claim_beats_the_name_id() -> None:
    claims = read_claims(facts(attributes=dict(ENTRA_ATTRIBUTES), name_id="pseudonym"))

    assert claims.external_id == "9f1c-entra-oid"


def test_a_username_that_is_an_email_fills_in_the_email() -> None:
    claims = read_claims(facts(attributes={"uid": ["ada.bergman@demo.local"]}))

    assert claims.user_name == "ada.bergman@demo.local"
    assert claims.email == "ada.bergman@demo.local"


def test_a_username_that_is_not_an_email_is_not_treated_as_one() -> None:
    """Better to refuse than to write "ada.bergman" into the email column and have
    it look like a real address everywhere afterwards."""
    with pytest.raises(UnusableAssertion):
        read_claims(facts(attributes={"uid": ["ada.bergman"]}))


def test_a_login_with_no_attributes_at_all_is_refused() -> None:
    """Almost always a provider nobody told which attributes to send."""
    with pytest.raises(UnusableAssertion, match="attributes"):
        read_claims(facts(attributes={}))


def test_an_email_name_id_is_enough_on_its_own() -> None:
    """A provider sending only an emailAddress NameID is a normal setup, not a broken
    one, and refusing it was wrong.

    Found while registering a real Okta tenant: Okta's app-creation wizard offers no
    attribute-statement fields at all — they are added afterwards, on a different
    screen — so the default path through its console produces exactly this assertion.
    """
    claims = read_claims(facts(attributes={}, name_id="ada.bergman@demo.local"))

    assert claims.user_name == "ada.bergman@demo.local"
    assert claims.email == "ada.bergman@demo.local"


def test_a_persistent_name_id_is_still_not_an_email() -> None:
    """The guard on the fallback above, and the reason it checks shape rather than the
    provider's declared format.

    A persistent NameID is an opaque provider-specific string. Accepting it as an
    email would look like a successful login and leave nonsense in the directory,
    which is worse than a refusal that says what to fix.
    """
    with pytest.raises(UnusableAssertion, match="attributes"):
        read_claims(facts(attributes={}, name_id="persistent-pseudonym-0001"))


def test_a_declared_email_format_does_not_override_the_shape_check() -> None:
    """Providers are inconsistent about NameID formats, so the format string is not
    trusted — the same reason attribute names are folded for case."""
    with pytest.raises(UnusableAssertion):
        read_claims(
            facts(
                attributes={},
                name_id="not-an-address",
                name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            )
        )


def test_an_email_attribute_beats_the_name_id() -> None:
    """The fallback is a last resort. An attribute is the provider stating a fact
    deliberately; a NameID that happens to look like an address is not."""
    claims = read_claims(
        facts(
            attributes={"email": ["ada.bergman@demo.local"]},
            name_id="someone.else@demo.local",
        )
    )

    assert claims.email == "ada.bergman@demo.local"
    assert claims.user_name == "ada.bergman@demo.local"


def test_the_name_id_is_still_the_external_id_when_it_supplied_the_email() -> None:
    """Both uses at once, which is fine: it is the provider's handle for this person
    and also, in this configuration, their address."""
    claims = read_claims(facts(attributes={}, name_id="ada.bergman@demo.local"))

    assert claims.external_id == "ada.bergman@demo.local"


def test_blank_claim_values_are_ignored() -> None:
    """A provider that sends the attribute but leaves it empty is the same as one
    that didn't send it, and must not produce a blank display name."""
    claims = read_claims(
        facts(
            attributes={
                "email": ["ada.bergman@demo.local"],
                "displayName": ["   "],
                "givenName": ["Ada"],
                "surname": ["Bergman"],
            }
        )
    )

    assert claims.display_name == "Ada Bergman"


def test_the_display_name_falls_back_to_the_username() -> None:
    claims = read_claims(facts(attributes={"email": ["ada.bergman@demo.local"]}))

    assert claims.display_name == "ada.bergman@demo.local"


# --------------------------------------------------------- building a person


def sample_claims(**overrides: object) -> IdentityClaims:
    defaults: dict[str, object] = {
        "user_name": "ada.bergman",
        "email": "ada.bergman@demo.local",
        "display_name": "Ada Bergman",
        "given_name": "Ada",
        "family_name": "Bergman",
        "external_id": "persistent-pseudonym-0001",
    }
    defaults.update(overrides)
    return IdentityClaims(**defaults)  # type: ignore[arg-type]


def test_someone_created_by_logging_in_is_marked_as_such() -> None:
    user = build_user(sample_claims())

    assert user.source is IdentitySource.JIT
    assert user.active is True


def test_logging_in_never_makes_anybody_an_admin() -> None:
    """There must be no path from "the provider let them in" to "they can change
    things here". That stays a decision somebody makes in the console."""
    assert build_user(sample_claims()).platform_role is PlatformRole.EMPLOYEE


# ------------------------------------------------------- refreshing a person


def existing_user(source: IdentitySource, **overrides: object) -> User:
    user = User(
        external_id=None,
        user_name="ada.bergman",
        email="old@demo.local",
        given_name="Ada",
        family_name="Olsen",
        display_name="Ada Olsen",
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=source,
    )
    for field, value in overrides.items():
        setattr(user, field, value)
    return user


def test_a_person_created_by_logging_in_gets_refreshed_from_the_provider() -> None:
    user = existing_user(IdentitySource.JIT)

    changed = refresh_user(user, sample_claims())

    assert user.email == "ada.bergman@demo.local"
    assert user.family_name == "Bergman"
    assert set(changed) >= {"email", "family_name", "display_name"}


def test_a_person_somebody_typed_in_is_left_alone() -> None:
    """Silently reverting an admin's edit on the next login would be a genuinely
    confusing bug to be on the receiving end of."""
    user = existing_user(IdentitySource.MANUAL)

    changed = refresh_user(user, sample_claims())

    assert user.email == "old@demo.local"
    assert user.display_name == "Ada Olsen"
    assert "email" not in changed


def test_a_missing_external_id_gets_filled_in_whoever_owns_the_record() -> None:
    """This is how somebody SCIM created gets linked to their logins, so it has to
    happen even for records this flow doesn't own."""
    user = existing_user(IdentitySource.SCIM)

    changed = refresh_user(user, sample_claims())

    assert user.external_id == "persistent-pseudonym-0001"
    assert changed == ("external_id",)


def test_an_existing_external_id_is_never_overwritten() -> None:
    """SCIM's identifier for someone is not ours to change."""
    user = existing_user(IdentitySource.SCIM, external_id="scim-id-42")

    changed = refresh_user(user, sample_claims())

    assert user.external_id == "scim-id-42"
    assert changed == ()


# -------------------------------------------------- matching against the directory


@pytest.mark.integration
async def test_matches_an_existing_person_by_external_id(db_session: AsyncSession) -> None:
    """External id beats userName, because emails change and external ids don't."""
    existing = build_user(sample_claims(user_name="ada.old@demo.local"))
    db_session.add(existing)
    await db_session.flush()

    found = await find_user(db_session, sample_claims(user_name="ada.new@demo.local"))

    assert found is not None
    assert found.id == existing.id


@pytest.mark.integration
async def test_matches_an_existing_person_by_username_ignoring_case(
    db_session: AsyncSession,
) -> None:
    existing = build_user(sample_claims(external_id=None))
    db_session.add(existing)
    await db_session.flush()

    found = await find_user(db_session, sample_claims(external_id=None, user_name="Ada.Bergman"))

    assert found is not None
    assert found.id == existing.id


@pytest.mark.integration
async def test_a_first_login_creates_the_person(db_session: AsyncSession) -> None:
    outcome = await provision_user(db_session, sample_claims(user_name="brand.new@demo.local"))

    assert outcome.created
    assert outcome.user.id is not None
    assert outcome.user.source is IdentitySource.JIT


@pytest.mark.integration
async def test_a_second_login_does_not_create_a_duplicate(db_session: AsyncSession) -> None:
    """The failure this guards against is quiet: a second account for one person,
    with the first one stranded and still holding whatever access it had."""
    first = await provision_user(db_session, sample_claims())
    second = await provision_user(db_session, sample_claims())

    assert first.user.id == second.user.id
    assert not second.created
