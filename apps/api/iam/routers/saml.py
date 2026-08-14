"""The login endpoints.

/saml/metadata  the document you hand a provider when registering this app
/saml/login     sends someone off to the provider to sign in
/saml/acs       where the provider posts the answer (next piece of work)

These live outside /api on purpose. A provider posts to them directly from the
person's browser, so they're part of the site rather than part of the JSON API,
and Caddy proxies them separately. See docs/adr/0003-single-origin.md.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select

from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.deps import SessionDep, app_settings
from iam.models.enums import ActorType, AuditOutcome
from iam.models.saml import IdentityProvider, SamlRequestState
from iam.saml.sp import (
    REQUEST_TTL,
    ServiceProvider,
    build_authn_request,
    is_safe_return_path,
    login_redirect_url,
    new_relay_state,
    new_request_id,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/saml", tags=["saml"])

SAML_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"


def _service_provider(settings: Annotated[Settings, Depends(app_settings)]) -> ServiceProvider:
    """Who we are, worked out from the address we're served on."""
    return ServiceProvider.from_base_url(settings.base_url)


SpDep = Annotated[ServiceProvider, Depends(_service_provider)]


@router.get(
    "/metadata",
    summary="Our details, for registering this app with a provider",
    response_class=Response,
    responses={200: {"content": {SAML_METADATA_MEDIA_TYPE: {}}}},
)
async def metadata(sp: SpDep) -> Response:
    """Hand this to whoever runs the identity provider.

    Deliberately not behind a login. It contains nothing secret — just our name and
    the address to send answers to — and needing to be signed in to fetch the thing
    you need in order to sign in would be an awkward loop.
    """
    return Response(content=sp.metadata_xml(), media_type=SAML_METADATA_MEDIA_TYPE)


@router.get(
    "/login",
    summary="Start signing in",
    # Has to match what the handler actually returns, or the published schema lies
    # about it. 303 rather than 307 because 307 keeps the method and body, and the
    # provider's login page is a plain GET.
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
)
async def login(
    request: Request,
    session: SessionDep,
    sp: SpDep,
    idp: Annotated[str, Query(description="Which provider to use, by short name")] = "authentik",
    return_to: Annotated[str, Query(description="Where to land afterwards")] = "/",
) -> RedirectResponse:
    """Send someone to their provider to sign in.

    Three things happen before the redirect: we check the provider is one we know,
    we check where they've asked to be sent afterwards, and we write down the
    request so the answer can be matched to it later.

    That last part is why this can't be stateless. The answer arrives as a
    cross-site form POST and browsers don't send our cookies on those, so the
    request has to be remembered server-side, keyed by a token that travels with it.
    """
    provider = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.slug == idp,
            IdentityProvider.enabled.is_(True),
        )
    )
    if provider is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"No identity provider called {idp!r} is set up and enabled.",
        )

    # Refuse to be turned into a redirect service. A login link that sends people
    # somewhere else afterwards looks completely legitimate, because it starts at a
    # real login page on a real domain.
    if not is_safe_return_path(return_to):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="return_to has to be a path on this site, like /users.",
        )

    now = dt.datetime.now(dt.UTC)

    # Clear out requests nobody ever finished. Doing it here rather than on a timer
    # keeps the table small without needing a scheduled job, and there's no reason
    # to hurry: an expired row is harmless, just useless.
    await session.execute(delete(SamlRequestState).where(SamlRequestState.expires_at < now))

    request_id = new_request_id()
    relay_state = new_relay_state()

    session.add(
        SamlRequestState(
            relay_state=relay_state,
            request_id=request_id,
            idp_slug=provider.slug,
            return_to=return_to,
            expires_at=now + REQUEST_TTL,
        )
    )

    authn_request = build_authn_request(
        sp=sp,
        idp_sso_url=provider.sso_url,
        request_id=request_id,
        issued_at=now,
    )

    client_ip = request.client.host if request.client else None
    await append_event(
        session,
        AuditDraft(
            action="saml.login_started",
            actor_type=ActorType.SYSTEM,
            actor_label="Anonymous visitor",
            outcome=AuditOutcome.SUCCESS,
            target_type="identity_provider",
            target_id=str(provider.id),
            target_label=provider.name,
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent"),
            detail={
                "request_id": request_id,
                "return_to": return_to,
                "idp": provider.slug,
            },
        ),
    )
    await session.commit()

    logger.info(
        "saml.login_started",
        extra={"idp": provider.slug, "request_id": request_id},
    )

    # 303 rather than 307. A 307 tells the browser to keep the method and body,
    # which is wrong here: the provider's login page is a GET, and sending anything
    # else confuses some providers.
    return RedirectResponse(
        url=login_redirect_url(
            idp_sso_url=provider.sso_url,
            authn_request_xml=authn_request,
            relay_state=relay_state,
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
