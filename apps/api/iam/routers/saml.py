"""The login endpoints.

/saml/metadata  the document you hand a provider when registering this app
/saml/login     sends someone off to the provider to sign in
/saml/acs       where the provider posts the answer

These live outside /api on purpose. A provider posts to them directly from the
person's browser, so they're part of the site rather than part of the JSON API,
and Caddy proxies them separately. See docs/adr/0003-single-origin.md.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.deps import SessionDep, SettingsDep, app_settings
from iam.models.enums import ActorType, AuditOutcome
from iam.models.saml import IdentityProvider, SamlAssertionSeen, SamlRequestState
from iam.saml.checks import (
    AssertionFacts,
    Expectations,
    MalformedResponse,
    all_passed,
    failed_names,
    run_all_checks,
)
from iam.saml.provisioning import UnusableAssertion, provision_user, read_claims
from iam.saml.sessions import create_session, set_session_cookie
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

ASSERTION_MEMORY_FALLBACK = dt.timedelta(hours=12)
"""How long to remember a login that never said when it expires.

Longer than a normal assertion's lifetime, not shorter, and that's the right way
round: a login with no stated expiry never fails the timing check, so forgetting
it early is exactly when a replay would start working again.
"""


def _service_provider(settings: Annotated[Settings, Depends(app_settings)]) -> ServiceProvider:
    """Who we are, worked out from the address we're served on."""
    return ServiceProvider.from_base_url(settings.base_url)


SpDep = Annotated[ServiceProvider, Depends(_service_provider)]

ResponseReader = Callable[[str, str], AssertionFacts]
"""Takes the posted response and the provider's certificate, gives back the facts."""


def _response_reader() -> ResponseReader:
    """Hand back the function that reads and signature-checks a login.

    A dependency rather than a plain import, for two reasons.

    reader.py is the only module that needs xmlsec, which doesn't install on
    Windows, so importing it at the top of this file would stop the whole app
    being importable on a developer's laptop. Importing it in here defers that to
    the one request that actually needs it. See ADR 0004.

    It also means a test can swap in a reader that returns prepared facts, so
    everything after the signature check — the checks, creating the person,
    issuing the session, the cookie, the redirect — is covered on any machine and
    in CI, where xmlsec isn't installed either. Nothing about the real
    cryptography is faked away: verifying signatures stays reader.py's job and is
    exercised in the container.
    """
    from iam.saml.reader import read_response

    return read_response


ReaderDep = Annotated[ResponseReader, Depends(_response_reader)]


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


async def _refuse_login(
    *,
    session: AsyncSession,
    request: Request,
    status_code: int,
    detail: str,
    idp_slug: str | None = None,
    extra: dict[str, Any] | None = None,
) -> NoReturn:
    """Write down why a login was turned away, then turn it away.

    Every rejection goes through here so none of them can be silent. A login that
    fails and leaves no trace is the worst case for whoever has to work out why
    somebody can't get in, and it's also how a sustained attempt to forge logins
    would go unnoticed.

    The entry is committed on its own. The login it describes is being thrown
    away, so there's nothing else to keep it company in the transaction.
    """
    await append_event(
        session,
        AuditDraft(
            action="saml.login_failed",
            actor_type=ActorType.IDP,
            actor_label=f"Upstream IdP <{idp_slug or 'unknown'}>",
            outcome=AuditOutcome.FAILURE,
            target_type="identity_provider",
            target_label=idp_slug,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": detail, **(extra or {})},
        ),
    )
    await session.commit()

    logger.warning("saml.login_failed", extra={"idp": idp_slug, "reason": detail})
    raise HTTPException(status_code, detail=detail)


@router.post(
    "/acs",
    summary="Where the provider posts the answer",
    # 303 because what a browser gets back from a successful login is a redirect
    # onwards, not a document. 307 would keep the method and re-POST the
    # assertion at whatever page they were heading for.
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
)
async def assertion_consumer_service(
    request: Request,
    session: SessionDep,
    sp: SpDep,
    settings: SettingsDep,
    read_response: ReaderDep,
    saml_response: Annotated[str, Form(alias="SAMLResponse")],
    relay_state: Annotated[str | None, Form(alias="RelayState")] = None,
) -> RedirectResponse:
    """Accept a login from the provider, or refuse it and say which check failed.

    This is the endpoint that has to be right. Everything the provider sends
    arrives through the person's own browser, so all of it is under the control of
    whoever is trying to get in. Nothing here is trusted until it has been through
    every check in checks.py, and nothing is trusted a second time because the
    request it answers is consumed whether the login is accepted or not.

    The order is: find the request this is answering, work out which provider that
    was, read and verify the document, run every check, and only then look up a
    person. Reading identity out of a document before checking it is the mistake
    that makes all the other checks pointless.

    Only replies to logins we started. A provider can also start one by itself,
    from a tile in its own dashboard, and that has no request to match against —
    which means giving up the check that stops someone posting a login at us out
    of the blue. checks.py handles that case, so turning it on later is a small
    change, but it stays off until there's a reason to want it.

    Raises:
        HTTPException: 400 for a login that can't be matched, read, or identified.
            401 for one that fails a check. 403 for a deactivated account.
    """
    now = dt.datetime.now(dt.UTC)
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    if not relay_state:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "This login has no RelayState, so it isn't answering a request we "
                "sent. Start at /saml/login."
            ),
        )

    state = await session.scalar(
        select(SamlRequestState).where(SamlRequestState.relay_state == relay_state)
    )
    if state is None:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "We have no record of sending this login request. It may have "
                "already been answered, or it may have expired. Start again at "
                "/saml/login."
            ),
        )

    # Copied out now, because the row is deleted below and we still need them.
    idp_slug = state.idp_slug
    expected_request_id = state.request_id
    return_to = state.return_to

    # One answer per request, accepted or not. Removing it here rather than after
    # the checks is what stops the same assertion being retried until something
    # lines up — a captured login is otherwise good for as long as the request
    # state sits there.
    await session.execute(
        delete(SamlRequestState).where(SamlRequestState.relay_state == relay_state)
    )

    if state.expires_at <= now:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This login took too long and the request has expired. Please try again.",
            idp_slug=idp_slug,
        )

    provider = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.slug == idp_slug,
            IdentityProvider.enabled.is_(True),
        )
    )
    if provider is None:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"The provider {idp_slug!r} was turned off or removed while this "
                "login was in progress."
            ),
            idp_slug=idp_slug,
        )

    try:
        facts = read_response(saml_response, provider.signing_cert)
    except MalformedResponse as exc:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"The login could not be read: {exc}",
            idp_slug=idp_slug,
        )

    already_seen = (
        await session.scalar(
            select(SamlAssertionSeen.assertion_id).where(
                SamlAssertionSeen.assertion_id == facts.assertion_id
            )
        )
        is not None
    )

    results = run_all_checks(
        facts,
        Expectations(
            our_entity_id=sp.entity_id,
            our_acs_url=sp.acs_url,
            idp_entity_id=provider.entity_id,
            expected_request_id=expected_request_id,
            require_signed_assertion=provider.want_signed_assertions,
        ),
        now=now,
        already_seen=already_seen,
    )
    # Stored on every outcome, not just failures. This list is the login
    # inspector: nine named results say "the clock is off", where a single
    # pass/fail says "invalid assertion" and leaves you guessing.
    checks = [result.as_dict() for result in results]

    if not all_passed(results):
        failed = failed_names(results)
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"This login failed {len(failed)} of its checks: {', '.join(failed)}.",
            idp_slug=idp_slug,
            extra={"checks": checks, "assertion_id": facts.assertion_id},
        )

    try:
        claims = read_claims(facts)
    except UnusableAssertion as exc:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
            idp_slug=idp_slug,
            extra={"checks": checks, "attributes": sorted(facts.attributes)},
        )

    outcome = await provision_user(session, claims)

    # A provider will happily sign someone in who we've switched off here. Ours is
    # the answer that counts, and this is the check P4's "someone left" flow
    # depends on holding.
    if not outcome.user.active:
        await _refuse_login(
            session=session,
            request=request,
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated.",
            idp_slug=idp_slug,
            extra={"checks": checks, "user_name": claims.user_name},
        )

    # Remember the assertion so it can't be used again. Written before the session
    # exists, so the two go into the same transaction and there's no window where
    # somebody is signed in by a login we've forgotten.
    session.add(
        SamlAssertionSeen(
            assertion_id=facts.assertion_id,
            issuer=facts.issuer,
            not_on_or_after=facts.not_on_or_after or now + ASSERTION_MEMORY_FALLBACK,
            detail={
                "idp": idp_slug,
                "user_id": str(outcome.user.id),
                "user_name": outcome.user.user_name,
                "request_id": expected_request_id,
            },
        )
    )

    # Same reasoning as the cleanup in login(): once a remembered login is past its
    # expiry it fails the timing check anyway, so there's nothing left to protect.
    await session.execute(delete(SamlAssertionSeen).where(SamlAssertionSeen.not_on_or_after < now))

    saml_session, token = await create_session(
        session,
        user_id=outcome.user.id,
        idp_slug=idp_slug,
        name_id=facts.name_id or claims.user_name,
        name_id_format=facts.name_id_format,
        session_index=facts.session_index,
        issued_at=now,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    if outcome.created:
        await append_event(
            session,
            AuditDraft(
                action="user.created",
                actor_type=ActorType.IDP,
                actor_label=f"Upstream IdP <{idp_slug}>",
                outcome=AuditOutcome.SUCCESS,
                target_type="user",
                target_id=str(outcome.user.id),
                target_label=outcome.user.user_name,
                ip_address=client_ip,
                user_agent=user_agent,
                detail={
                    "reason": "first login, and SCIM had not sent them yet",
                    "source": "jit",
                    "idp": idp_slug,
                },
            ),
        )

    await append_event(
        session,
        AuditDraft(
            action="saml.login_succeeded",
            actor_type=ActorType.USER,
            actor_id=outcome.user.id,
            actor_label=f"{outcome.user.display_name} <{outcome.user.user_name}>",
            outcome=AuditOutcome.SUCCESS,
            target_type="identity_provider",
            target_id=str(provider.id),
            target_label=provider.name,
            ip_address=client_ip,
            user_agent=user_agent,
            detail={
                "idp": idp_slug,
                "assertion_id": facts.assertion_id,
                "request_id": expected_request_id,
                "session_id": str(saml_session.id),
                "session_index": facts.session_index,
                "directory": outcome.summary,
                "checks": checks,
            },
        ),
    )

    await session.commit()

    logger.info(
        "saml.login_succeeded",
        extra={
            "idp": idp_slug,
            "user_id": str(outcome.user.id),
            "session_id": str(saml_session.id),
            "created_user": outcome.created,
        },
    )

    # Checked again on the way out, even though login() checked it on the way in.
    # It's one comparison, and it means a tampered-with row in the database can't
    # turn a successful login into a redirect to somebody else's site.
    destination = return_to if is_safe_return_path(return_to) else "/"

    response = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, token, settings=settings)
    return response
