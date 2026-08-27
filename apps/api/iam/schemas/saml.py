"""Shapes for registering and listing identity providers.

The certificate is deliberately not in the summary. It's a wall of base64 that
makes a list unreadable, and there's a fingerprint instead for the thing people
actually want to know from a list: whether the key is still the one they expect.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field


class IdentityProviderRegistration(BaseModel):
    """Register a provider, or update one that already exists.

    The metadata document carries the entity id, the addresses and the
    certificate, so none of those are fields here. Letting somebody type them
    separately is how you end up trusting a key the provider never published.
    See docs/adr/0006-paste-metadata-do-not-fetch-it.md.
    """

    slug: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
        description=(
            "Short name used in the login URL, e.g. /saml/login?idp=authentik. "
            "Lowercase, digits and dashes, because it goes in a query string."
        ),
    )
    name: str = Field(min_length=1, max_length=255, description="What to call it in the console.")
    metadata_xml: str = Field(
        min_length=1,
        description="The provider's SAML metadata document, pasted in whole.",
    )
    enabled: bool = Field(
        default=True,
        description="Turn a provider off to stop new logins without losing its settings.",
    )
    want_signed_assertions: bool = Field(
        default=True,
        description=(
            "Insist the assertion itself is signed, not just the response wrapped "
            "around it. Only turn this off for a provider that genuinely cannot do "
            "it, because signing only the wrapper leaves the contents swappable."
        ),
    )


class SignInOption(BaseModel):
    """One way to sign in, for the screen shown to somebody who is not signed in yet.

    Deliberately thin. This is the only unauthenticated view of the provider table, so
    it carries what a button needs and nothing else: a name to print and a URL to send
    them to. No entity id, no certificate, no timestamps, no enabled flag — a disabled
    provider simply is not in the list.

    Publishing the names of the providers we accept is not a leak. Every login page on
    the internet does it, and it has to: somebody who cannot see "Sign in with Okta"
    cannot sign in with Okta. What would be a leak is the SSO URL, the entity id or the
    certificate, and none of those are here.
    """

    slug: str
    name: str
    login_url: str


class IdentityProviderSummary(BaseModel):
    """A registered provider, without the wall of base64."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    enabled: bool
    entity_id: str
    sso_url: str
    slo_url: str | None
    want_signed_assertions: bool
    created_at: dt.datetime
    updated_at: dt.datetime

    login_url: str = Field(description="Where to send somebody to sign in with this provider.")
    certificate_fingerprint: str = Field(
        description=(
            "The first and last few characters of the signing certificate. Enough "
            "to see at a glance that the key has changed, which is otherwise a "
            "diff of two blocks of base64."
        )
    )


class IdentityProviderDetail(IdentityProviderSummary):
    """One provider, including the certificate in full."""

    signing_cert: str = Field(
        description=(
            "The certificate every login from this provider is checked against. "
            "This is the whole basis of trust for it."
        )
    )
