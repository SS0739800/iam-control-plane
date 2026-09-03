"""Registering the providers we accept logins from.

Registering one is the most consequential write in this system. The
certificate that lands on the row becomes the thing every future login is
checked against, so whoever can change it can decide who gets to be anybody.
That's why it needs its own permission rather than borrowing apps:write, and
why every change here is audited with the certificate fingerprint attached.

The document is pasted in. We never fetch a metadata URL — see
docs/adr/0006-paste-metadata-do-not-fetch-it.md before adding that
convenience back.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep, SettingsDep
from iam.models.enums import ActorType, AuditOutcome
from iam.models.saml import IdentityProvider
from iam.saml.metadata import UnreadableMetadata, certificate_fingerprint, read_idp_metadata
from iam.schemas.saml import (
    IdentityProviderDetail,
    IdentityProviderRegistration,
    IdentityProviderSummary,
    SignInOption,
)
from iam.security import Actor, Permission, require

router = APIRouter(prefix="/identity-providers", tags=["identity providers"])


def _summary(provider: IdentityProvider, *, base_url: str) -> IdentityProviderSummary:
    return IdentityProviderSummary(
        id=provider.id,
        slug=provider.slug,
        name=provider.name,
        enabled=provider.enabled,
        entity_id=provider.entity_id,
        sso_url=provider.sso_url,
        slo_url=provider.slo_url,
        want_signed_assertions=provider.want_signed_assertions,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
        login_url=f"{base_url.rstrip('/')}/saml/login?idp={provider.slug}",
        certificate_fingerprint=certificate_fingerprint(provider.signing_cert),
    )


def _detail(provider: IdentityProvider, *, base_url: str) -> IdentityProviderDetail:
    return IdentityProviderDetail(
        **_summary(provider, base_url=base_url).model_dump(),
        signing_cert=provider.signing_cert,
    )


@router.get(
    "/sign-in-options",
    response_model=list[SignInOption],
    summary="Ways to sign in, for somebody who is not signed in yet",
)
async def sign_in_options(session: SessionDep, settings: SettingsDep) -> list[SignInOption]:
    """The providers a signed-out visitor can choose from.

    Unauthenticated, the only endpoint here that is. Everything else about a
    provider needs idp:read, but a login screen can't ask for a permission —
    the person reading it has no session yet, which is why they're looking
    at it.

    The console used to solve this by hard-coding ?idp=authentik into the
    sign-in button, which worked locally and pointed at a provider that
    didn't exist in production. Somebody had to be handed a URL to get in
    at all.

    Only enabled providers: a disabled one isn't a way to sign in, and
    offering it would produce a refusal that looks like a fault.

    Declared before the "" route below it: FastAPI matches in order, and
    "/{slug}" would otherwise swallow this path and try to look up a
    provider called "sign-in-options".
    """
    rows = (
        await session.scalars(
            select(IdentityProvider)
            .where(IdentityProvider.enabled.is_(True))
            .order_by(IdentityProvider.name)
        )
    ).all()
    root = settings.base_url.rstrip("/")
    return [
        SignInOption(
            slug=provider.slug,
            name=provider.name,
            login_url=f"{root}/saml/login?idp={provider.slug}",
        )
        for provider in rows
    ]


@router.get(
    "",
    response_model=list[IdentityProviderSummary],
    summary="List the providers we accept logins from",
    dependencies=[Depends(require(Permission.IDP_READ))],
)
async def list_identity_providers(
    session: SessionDep, settings: SettingsDep
) -> list[IdentityProviderSummary]:
    """Every registered provider, enabled or not.

    Not paginated. There are three of these at most, and there's never going
    to be a fourth page of identity providers.
    """
    rows = (await session.scalars(select(IdentityProvider).order_by(IdentityProvider.name))).all()
    return [_summary(provider, base_url=settings.base_url) for provider in rows]


@router.get(
    "/{slug}",
    response_model=IdentityProviderDetail,
    summary="One provider, with its certificate",
    dependencies=[Depends(require(Permission.IDP_READ))],
)
async def get_identity_provider(
    slug: str, session: SessionDep, settings: SettingsDep
) -> IdentityProviderDetail:
    provider = await session.scalar(select(IdentityProvider).where(IdentityProvider.slug == slug))
    if provider is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No provider called {slug!r}.")
    return _detail(provider, base_url=settings.base_url)


@router.post(
    "",
    response_model=IdentityProviderDetail,
    status_code=status.HTTP_200_OK,
    summary="Register a provider from its metadata, or update one",
)
async def register_identity_provider(
    payload: IdentityProviderRegistration,
    session: SessionDep,
    settings: SettingsDep,
    actor: Annotated[Actor, Depends(require(Permission.IDP_WRITE))],
) -> IdentityProviderDetail:
    """Read a provider's metadata and store what it says.

    Registering the same slug again replaces the details, which is how this
    handles a certificate rotation: paste the new metadata, the row updates.
    A POST that isn't create-only, since a separate "update" endpoint would
    take the same document and do the same work, and having two would just
    mean guessing which one to use.

    The audit entry records the old and new certificate fingerprints
    whenever the key changes, so a key changing when nobody rotated one
    shows up in the log.

    Raises:
        HTTPException: 400 if the metadata can't be read or is missing something.
            409 if another slug has already claimed the same entity id.
    """
    try:
        metadata = read_idp_metadata(payload.metadata_xml)
    except UnreadableMetadata as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"That metadata could not be used: {exc}",
        ) from exc

    existing = await session.scalar(
        select(IdentityProvider).where(IdentityProvider.slug == payload.slug)
    )

    # Two slugs pointing at one provider would make logins ambiguous: an
    # assertion says which entity issued it, not which of our rows to check
    # it against.
    clash = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.entity_id == metadata.entity_id,
            IdentityProvider.slug != payload.slug,
        )
    )
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"{metadata.entity_id} is already registered as {clash.slug!r}. "
                "Update that one instead of adding a second name for it."
            ),
        )

    previous_fingerprint = certificate_fingerprint(existing.signing_cert) if existing else None
    new_fingerprint = certificate_fingerprint(metadata.signing_cert)

    provider = existing or IdentityProvider(slug=payload.slug)
    provider.name = payload.name
    provider.enabled = payload.enabled
    provider.want_signed_assertions = payload.want_signed_assertions
    provider.entity_id = metadata.entity_id
    provider.sso_url = metadata.sso_url
    provider.slo_url = metadata.slo_url
    provider.signing_cert = metadata.signing_cert

    if existing is None:
        session.add(provider)
    await session.flush()

    certificate_changed = previous_fingerprint is not None and (
        previous_fingerprint != new_fingerprint
    )

    await append_event(
        session,
        AuditDraft(
            action="idp.updated" if existing else "idp.registered",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="identity_provider",
            target_id=str(provider.id),
            target_label=provider.slug,
            detail={
                "entity_id": provider.entity_id,
                "sso_url": provider.sso_url,
                "slo_url": provider.slo_url,
                "enabled": provider.enabled,
                "want_signed_assertions": provider.want_signed_assertions,
                "certificate_fingerprint": new_fingerprint,
                "previous_certificate_fingerprint": previous_fingerprint,
                "certificate_changed": certificate_changed,
            },
        ),
    )
    await session.commit()

    # Reload before reading anything off the row. updated_at is set by the
    # database through onupdate, so after an UPDATE that attribute is
    # expired, and touching an expired attribute needs a query, which plain
    # attribute access can't do under asyncio — it fails as MissingGreenlet,
    # not with anything that mentions timestamps.
    await session.refresh(provider)

    return _detail(provider, base_url=settings.base_url)
