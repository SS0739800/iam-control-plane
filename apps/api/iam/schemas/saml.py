"""Shapes for registering and listing identity providers.

The certificate is left out of the summary (it's a wall of base64) in
favor of a short fingerprint, enough to tell if the key changed.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field


class IdentityProviderRegistration(BaseModel):
    """Register a provider, or update one that already exists.

    Entity id, addresses, and certificate come from the pasted metadata
    document, not typed fields, so we never trust a key the provider didn't
    actually publish. See docs/adr/0006-paste-metadata-do-not-fetch-it.md.
    """

    slug: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
        description="Short name used in the login URL, e.g. "
        "/saml/login?idp=authentik. Lowercase, digits, and dashes only.",
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
        description="Require the assertion itself to be signed, not just "
        "the response wrapper. Turn off only if the provider can't sign it.",
    )


class SignInOption(BaseModel):
    """One way to sign in, shown to someone not yet signed in.

    Only carries a name and a URL — no entity id, certificate, timestamps,
    or enabled flag (a disabled provider is just absent from the list).
    Publishing provider names isn't a leak; every login page does it. The
    SSO URL, entity id, and certificate would be, and aren't included.
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
        description="First and last few characters of the signing "
        "certificate, enough to spot at a glance if the key changed."
    )


class IdentityProviderDetail(IdentityProviderSummary):
    """One provider, including the certificate in full."""

    signing_cert: str = Field(
        description="The certificate every login from this provider is checked against."
    )
