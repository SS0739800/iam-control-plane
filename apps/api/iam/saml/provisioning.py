"""Turning a verified login into a person in our directory.

By the time anything here runs, the login has already passed every check in
checks.py. This file is only about the question that comes next: which row in
``users`` is this, and what do we do if there isn't one.

Two jobs, kept apart on purpose:

Reading the claims. Every provider spells the same handful of facts differently —
authentik sends ``http://schemas.goauthentik.io/2021/02/saml/username``, Entra
sends a WS-Federation claim URI, Okta often just sends ``email``. That's a
lookup table, not logic, and it lives in the CLAIM constants below.

Deciding what to do with them. Match an existing person, or create one. The
matching order matters and is explained on find_user.

No xmlsec and no XML here either, so this runs and is tested anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import IdentitySource, PlatformRole
from iam.models.user import User
from iam.saml.checks import AssertionFacts


class UnusableAssertion(Exception):
    """The login was genuine but doesn't say who it's for.

    Different from a failed check. Nothing was wrong with the document; it just
    didn't carry enough to identify a person, which is a provider configuration
    problem and needs a different error message.
    """


# Claim names, best first. A provider sends one or two of each of these, never
# all of them, so every list is tried in order and the first one with a value
# wins.
#
# These are deliberately data rather than if-statements: adding Okta or Entra
# should mean adding a string here, not editing the matching logic.

CLAIM_USER_NAME = (
    "http://schemas.goauthentik.io/2021/02/saml/username",
    "urn:oid:0.9.2342.19200300.100.1.1",  # uid
    "userName",
    "username",
    "uid",
)

CLAIM_EMAIL = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",  # mail
    "email",
    "emailAddress",
    "mail",
)

CLAIM_GIVEN_NAME = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "urn:oid:2.5.4.42",  # givenName
    "givenName",
    "firstName",
    "first_name",
)

CLAIM_FAMILY_NAME = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "urn:oid:2.5.4.4",  # sn
    "surname",
    "familyName",
    "lastName",
    "last_name",
)

CLAIM_DISPLAY_NAME = (
    "http://schemas.microsoft.com/identity/claims/displayname",
    "urn:oid:2.16.840.1.113730.3.1.241",  # displayName
    "displayName",
    "cn",
    # Last, and only for the display name. authentik puts a person's full name
    # here while Entra puts their sign-in name, so it's too ambiguous to trust
    # for anything that has to be exact.
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
)

CLAIM_EXTERNAL_ID = (
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "http://schemas.goauthentik.io/2021/02/saml/uid",
    "externalId",
)


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    """Who the provider says this is, in our own field names.

    These match the ``users`` columns, which match what SCIM calls things. P3
    hands the same facts back over SCIM, so there's one vocabulary throughout.
    """

    user_name: str
    email: str
    display_name: str
    given_name: str | None = None
    family_name: str | None = None
    external_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProvisionOutcome:
    """What happened to the directory as a result of this login."""

    user: User
    created: bool
    updated_fields: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        """One line for the audit entry and the log."""
        if self.created:
            return "created on first login"
        if self.updated_fields:
            return f"details refreshed from the provider: {', '.join(self.updated_fields)}"
        return "matched an existing person, nothing to change"


def _first_claim(attributes: dict[str, list[str]], names: tuple[str, ...]) -> str | None:
    """First non-empty value among these claim names, in the order given."""
    for name in names:
        for value in attributes.get(name, ()):
            stripped = value.strip()
            if stripped:
                return stripped
    return None


def _looks_like_an_email(value: str) -> bool:
    """Good enough to decide whether a username can double as an email address.

    Not validation. The provider is the authority on whether an address is real;
    this only answers "is it shaped like one", so we know whether falling back to
    it would put nonsense in the email column.
    """
    local, separator, domain = value.partition("@")
    return bool(separator) and bool(local) and "." in domain and not domain.endswith(".")


def read_claims(facts: AssertionFacts) -> IdentityClaims:
    """Pull the person's details out of a verified login.

    Raises:
        UnusableAssertion: The login carries no usable identifier, so there's
            nobody to sign in. Almost always a provider that hasn't been told
            which attributes to send.
    """
    attributes = facts.attributes

    email = _first_claim(attributes, CLAIM_EMAIL)
    user_name = _first_claim(attributes, CLAIM_USER_NAME)

    # Either can stand in for the other. Plenty of providers send only one, and a
    # username is an email address more often than not.
    if user_name is None and email is not None:
        user_name = email
    if email is None and user_name is not None and _looks_like_an_email(user_name):
        email = user_name

    if not user_name or not email:
        raise UnusableAssertion(
            "the login carries no email address or username, so there is nobody to "
            "sign in. Check which attributes the provider is configured to send."
        )

    given_name = _first_claim(attributes, CLAIM_GIVEN_NAME)
    family_name = _first_claim(attributes, CLAIM_FAMILY_NAME)

    display_name = _first_claim(attributes, CLAIM_DISPLAY_NAME)
    if not display_name:
        both = " ".join(part for part in (given_name, family_name) if part)
        display_name = both or user_name

    return IdentityClaims(
        user_name=user_name,
        email=email,
        display_name=display_name,
        given_name=given_name,
        family_name=family_name,
        # NameID is the fallback because we ask for the persistent format, which
        # is the provider's own stable id for this person. It doesn't change when
        # they get married or move team, and their email does.
        external_id=_first_claim(attributes, CLAIM_EXTERNAL_ID) or facts.name_id,
    )


async def find_user(db: AsyncSession, claims: IdentityClaims) -> User | None:
    """Find the person this login belongs to, if we already know them.

    External id first, userName second, and that order is the whole point. The
    external id is the provider's own handle for someone and never changes.
    Emails do change, and if we matched on email alone then somebody's first
    login after a name change would create a second account for them and quietly
    strand the first one.
    """
    if claims.external_id:
        by_external_id = await db.scalar(select(User).where(User.external_id == claims.external_id))
        if by_external_id is not None:
            return by_external_id

    # Case-insensitive, because providers are not consistent about it and
    # "Ada.Bergman@demo.local" is the same person as "ada.bergman@demo.local".
    # Annotated because func.lower() loses the row type and scalar() falls back
    # to Any, which strict mypy rejects at the return.
    by_user_name: User | None = await db.scalar(
        select(User).where(func.lower(User.user_name) == claims.user_name.lower())
    )
    return by_user_name


def refresh_user(user: User, claims: IdentityClaims) -> tuple[str, ...]:
    """Update a person's details from the login, and say what changed.

    Only touches records this flow created. A record SCIM owns gets overwritten
    on the next sync anyway, and a record somebody typed into the console is
    theirs — silently reverting an admin's edit on the next login would be a
    genuinely confusing bug to be on the receiving end of.

    The external id is the exception. It's set when it's missing, because that's
    how a person SCIM created gets linked to their logins, but never overwritten.
    """
    changed: list[str] = []

    if claims.external_id and user.external_id is None:
        user.external_id = claims.external_id
        changed.append("external_id")

    if user.source is not IdentitySource.JIT:
        return tuple(changed)

    for field, incoming in (
        ("email", claims.email),
        ("given_name", claims.given_name),
        ("family_name", claims.family_name),
        ("display_name", claims.display_name),
    ):
        if incoming and getattr(user, field) != incoming:
            setattr(user, field, incoming)
            changed.append(field)

    return tuple(changed)


def build_user(claims: IdentityClaims) -> User:
    """A new person, created because they logged in and we'd never seen them.

    Everyone starts as an employee. Nobody gets to be an admin by logging in;
    that's a decision somebody makes in the console afterwards, and having no
    path from "the provider let them in" to "they can change things here" is
    worth the extra step.
    """
    return User(
        external_id=claims.external_id,
        user_name=claims.user_name,
        email=claims.email,
        given_name=claims.given_name,
        family_name=claims.family_name,
        display_name=claims.display_name,
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.JIT,
    )


async def provision_user(db: AsyncSession, claims: IdentityClaims) -> ProvisionOutcome:
    """Match this login to a person, creating one if we've never seen them.

    Creating on first login is deliberate for P2. SCIM is what fills the
    directory properly, and that's P3; until then, a login from a provider we
    trust is enough to make an account. P4 revisits this — at that point an
    account created by logging in should probably start with no access at all
    rather than a default role.

    Does not commit. The caller does, so the new person and the audit entry
    saying they were created go in together.
    """
    existing = await find_user(db, claims)

    if existing is not None:
        return ProvisionOutcome(
            user=existing,
            created=False,
            updated_fields=refresh_user(existing, claims),
        )

    user = build_user(claims)
    db.add(user)
    await db.flush()
    return ProvisionOutcome(user=user, created=True)
