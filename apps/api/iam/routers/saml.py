"""The login endpoints.

/saml/metadata  the document you hand a provider when registering this app
/saml/login     sends someone off to the provider to sign in
/saml/acs       where the provider posts the answer
/saml/logout    ends the session, and asks the provider to end theirs
/saml/sls       single logout, in both directions

These live outside /api on purpose. A provider posts to them directly from the
person's browser, so they're part of the site rather than part of the JSON API,
and Caddy proxies them separately. See docs/adr/0003-single-origin.md.

None of what we send is signed, here or at login. That's the same position most
service providers take and it works with a provider that doesn't insist. One that
does needs a key of ours, and that arrives in P5 when we start issuing logins
ourselves and need a key anyway.
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

from iam.access import reconcile, touches_rules
from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.deps import SessionDep, SettingsDep, app_settings
from iam.models.enums import ActorType, AuditOutcome
from iam.models.saml import IdentityProvider, SamlAssertionSeen, SamlRequestState, SamlSession
from iam.models.user import User
from iam.saml.checks import (
    AssertionFacts,
    Expectations,
    LogoutRequestFacts,
    LogoutResponseFacts,
    MalformedResponse,
    all_passed,
    failed_names,
    run_all_checks,
)
from iam.saml.provisioning import UnusableAssertion, provision_user, read_claims
from iam.saml.sessions import (
    RevokedReason,
    clear_session_cookie,
    create_session,
    find_by_token,
    revoke_by_name_id,
    revoke_by_session_index,
    revoke_session,
    set_session_cookie,
)
from iam.saml.sp import (
    REQUEST_TTL,
    ServiceProvider,
    build_authn_request,
    build_logout_request,
    build_logout_response,
    is_safe_return_path,
    login_redirect_url,
    new_relay_state,
    new_request_id,
    redirect_binding_url,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/saml", tags=["saml"])

SAML_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"

MAX_STORED_RESPONSE_CHARS = 32 * 1024
"""How much of a failed login's response to keep for the inspector.

A real one is a few kilobytes, so this keeps all of anything genuine and refuses to
let a deliberately enormous one bloat the audit log.
"""

ASSERTION_MEMORY_FALLBACK = dt.timedelta(hours=12)
"""How long to remember a login that never said when it expires.

Longer than a normal assertion's lifetime, not shorter, and that's the right way
round: a login with no stated expiry never fails the timing check, so forgetting
it early is exactly when a replay would start working again.
"""


def _service_provider(
    request: Request, settings: Annotated[Settings, Depends(app_settings)]
) -> ServiceProvider:
    """Who we are, worked out from the address we're served on.

    Carries the signing certificate so /saml/metadata can publish it. The keypair is
    built once at startup and lives on app.state — the same one P5 signs assertions
    with, because there is one identity here, not one per direction.
    """
    keypair = getattr(request.app.state, "saml_keypair", None)
    return ServiceProvider.from_base_url(
        settings.base_url,
        signing_certificate=keypair.certificate_body if keypair else None,
    )


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

LogoutRequestReader = Callable[[str, str], LogoutRequestFacts]
LogoutResponseReader = Callable[[str, str], LogoutResponseFacts]


def _logout_request_reader() -> LogoutRequestReader:
    """The function that reads a provider's logout request. Same seam as the login
    reader, for the same two reasons — see _response_reader."""
    from iam.saml.reader import read_logout_request

    return read_logout_request


def _logout_response_reader() -> LogoutResponseReader:
    """The function that reads a provider's logout confirmation."""
    from iam.saml.reader import read_logout_response

    return read_logout_response


LogoutRequestReaderDep = Annotated[LogoutRequestReader, Depends(_logout_request_reader)]
LogoutResponseReaderDep = Annotated[LogoutResponseReader, Depends(_logout_response_reader)]


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
    raw_response: str | None = None,
) -> NoReturn:
    """Write down why a login was turned away, then turn it away.

    Every rejection goes through here so none of them can be silent. A login that
    fails and leaves no trace is the worst case for whoever has to work out why
    somebody can't get in, and it's also how a sustained attempt to forge logins
    would go unnoticed.

    The entry is committed on its own. The login it describes is being thrown
    away, so there's nothing else to keep it company in the transaction.

    The response itself is kept on failures, and only on failures. It's the thing
    you actually need when a login stops working against a new provider, and the
    inspector shows it beside the check results. Successes don't get it: every
    check passed, so there's nothing to look at, and storing an assertion per login
    forever is a lot of somebody's personal data for no reason.
    """
    detail_payload: dict[str, Any] = {"reason": detail, **(extra or {})}

    if raw_response:
        detail_payload["raw_response"] = raw_response[:MAX_STORED_RESPONSE_CHARS]
        detail_payload["raw_response_truncated"] = len(raw_response) > MAX_STORED_RESPONSE_CHARS

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
            detail=detail_payload,
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
            raw_response=saml_response,
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
            raw_response=saml_response,
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
            raw_response=saml_response,
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
            raw_response=saml_response,
        )

    # Somebody arriving by logging in is a joiner too, and somebody whose
    # department changed at the provider brings that change in with their next
    # login. Both are the same question — what do the rules want now — so both run
    # the same reconcile. Skipped when nothing a rule reads moved, which is the
    # common case for a returning user.
    if outcome.created or touches_rules(outcome.updated_fields):
        rules_outcome = await reconcile(session, outcome.user)
        if rules_outcome.changed:
            logger.info(
                "saml.groups_reconciled",
                extra={
                    "user_name": outcome.user.user_name,
                    **rules_outcome.as_audit_detail(),
                },
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


@router.post(
    "/logout",
    summary="Sign out",
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
)
async def logout(
    request: Request,
    session: SessionDep,
    sp: SpDep,
    settings: SettingsDep,
) -> RedirectResponse:
    """End this session, clear the cookie, and tell the provider.

    A POST, not a GET. A sign-out you can trigger with a link means any page on
    the internet can sign our users out with an image tag pointed at it. Annoying
    rather than dangerous, but it costs nothing to get right, and the Lax cookie
    means a cross-site POST doesn't carry the session anyway.

    If the provider has a logout address, this ends with a redirect to it carrying
    a LogoutRequest, and the provider signs them out too. Without that step,
    clicking login again puts them straight back in without a password prompt,
    because the provider still thinks they're signed in — which is a surprising
    thing to watch happen right after pressing "sign out".

    Our own session is ended before the redirect, not after. If the provider is
    down or never answers, the person is still signed out here, which is the part
    we're responsible for.

    Always succeeds. No cookie, an unknown one, one that expired an hour ago:
    they all end with the person signed out and the cookie gone, which is what
    they asked for. Reporting an error for "you were already signed out" would be
    technically accurate and useless.
    """
    now = dt.datetime.now(dt.UTC)
    token = request.cookies.get(settings.session_cookie_name)

    # find_by_token rather than lookup_session: somebody whose session went idle
    # an hour ago still clicked the button, and their row should be marked ended
    # rather than left open until it expires on its own.
    existing = await find_by_token(session, token) if token else None

    if existing is not None and existing.revoked_at is None:
        await revoke_session(session, existing, reason=RevokedReason.SIGNED_OUT, now=now)

        user = await session.get(User, existing.user_id)
        await append_event(
            session,
            AuditDraft(
                action="saml.signed_out",
                actor_type=ActorType.USER,
                actor_id=existing.user_id,
                actor_label=(
                    f"{user.display_name} <{user.user_name}>" if user else str(existing.user_id)
                ),
                outcome=AuditOutcome.SUCCESS,
                target_type="saml_session",
                target_id=str(existing.id),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                detail={"idp": existing.idp_slug, "reason": RevokedReason.SIGNED_OUT},
            ),
        )
        await session.commit()

        logger.info(
            "saml.signed_out",
            extra={"session_id": str(existing.id), "user_id": str(existing.user_id)},
        )

    destination = "/"

    if existing is not None:
        keypair = getattr(request.app.state, "saml_keypair", None)
        onward = await _single_logout_url(
            session,
            sp=sp,
            saml_session=existing,
            now=now,
            private_key_pem=keypair.private_key_pem if keypair else None,
        )
        if onward is not None:
            destination = onward

    response = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response, settings=settings)
    return response


async def _single_logout_url(
    session: AsyncSession,
    *,
    sp: ServiceProvider,
    saml_session: SamlSession,
    now: dt.datetime,
    private_key_pem: str | None,
) -> str | None:
    """Where to send someone so the provider signs them out too, if it can.

    Returns None when there's nothing to do — the provider has no logout address,
    or we never recorded a NameID for this session and so have no way to say who to
    sign out. Both are ordinary, and both just mean the person stays signed in over
    there until that session expires on its own.

    The request is written down the same way a login request is, in
    saml_request_state, so the answer can be matched to it when it comes back to
    /saml/sls. Same table, same expiry sweep, same reasoning.
    """
    provider = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.slug == saml_session.idp_slug,
            IdentityProvider.enabled.is_(True),
        )
    )
    if provider is None or not provider.slo_url or not saml_session.name_id:
        return None

    request_id = new_request_id()
    relay_state = new_relay_state()

    session.add(
        SamlRequestState(
            relay_state=relay_state,
            request_id=request_id,
            idp_slug=provider.slug,
            return_to="/",
            expires_at=now + REQUEST_TTL,
        )
    )
    await session.commit()

    logout_request = build_logout_request(
        sp=sp,
        idp_slo_url=provider.slo_url,
        request_id=request_id,
        name_id=saml_session.name_id,
        name_id_format=saml_session.name_id_format,
        session_index=saml_session.session_index,
        issued_at=now,
    )

    logger.info(
        "saml.single_logout_started",
        extra={"idp": provider.slug, "request_id": request_id},
    )

    # Signed, because Okta refuses an unsigned LogoutRequest outright — which is how
    # single logout came to silently do nothing: our session ended, theirs did not,
    # and the next login walked back in without a password.
    return redirect_binding_url(
        provider.slo_url,
        saml_request=logout_request,
        relay_state=relay_state,
        private_key_pem=private_key_pem,
    )


async def _identify_logout_sender(
    session: AsyncSession,
    raw_request: str,
    read_logout_request: LogoutRequestReader,
) -> tuple[IdentityProvider, LogoutRequestFacts] | None:
    """Work out which provider sent this logout request, by whose key signed it.

    Every enabled provider's certificate is tried, and the one that verifies is the
    sender. That's deliberately not "read the Issuer and look it up" — the issuer is
    a field in an unverified document, so believing it means letting the document
    say who it's from. Trying keys instead means the signature is what identifies
    the sender, which is the only thing here that can.

    There are three providers at most, so trying each is cheaper than the round trip
    it would replace.

    Returns None when nothing verified, which covers both an unsigned request and
    one signed by a key we don't know.
    """
    providers = (
        await session.scalars(select(IdentityProvider).where(IdentityProvider.enabled.is_(True)))
    ).all()

    for provider in providers:
        try:
            facts = read_logout_request(raw_request, provider.signing_cert)
        except MalformedResponse:
            # Unreadable is unreadable, whichever key we tried it with.
            return None
        if facts.signature_verified:
            return provider, facts

    return None


# Registered twice rather than as one api_route with both methods, because that
# gives the two operations the same id and the generated TypeScript then has a
# name collision. Providers differ on which method they use and the message is
# identical either way, so both point at one handler.
@router.get(
    "/sls",
    summary="Single logout, in both directions",
    operation_id="single_logout_redirect_binding",
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
)
@router.post(
    "/sls",
    summary="Single logout, in both directions",
    operation_id="single_logout_post_binding",
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
)
async def single_logout_service(
    request: Request,
    session: SessionDep,
    sp: SpDep,
    settings: SettingsDep,
    read_logout_request: LogoutRequestReaderDep,
    read_logout_response: LogoutResponseReaderDep,
) -> RedirectResponse:
    """Handle a logout, whichever side started it.

    Two different things arrive here and they are told apart by which parameter is
    present, not by the method:

    A `SAMLResponse` is the provider confirming it signed somebody out because we
    asked. Our session was already ended before we sent that request, so there's
    nothing left to do but check it and send the person home.

    A `SAMLRequest` is the provider telling us somebody signed out somewhere else,
    or was signed out by an administrator. That one matters: it's the message that
    makes "remove their access" actually remove their access, everywhere, rather
    than only in the places they happen to visit next.

    Accepts GET and POST because providers differ on which they use, and the message
    is the same either way.

    We don't sign our answer. A provider that insists on signed logout messages
    won't accept it, and that needs a key of ours, which arrives in P5. authentik
    doesn't insist, so this works today; Okta and Entra may not, and that's a known
    limit rather than a surprise.

    Unsigned requests are refused. We can't tell who sent one, and accepting it
    would let anybody sign out anybody whose NameID they can guess. That's only a
    nuisance rather than a way in, but refusing costs nothing.
    """
    now = dt.datetime.now(dt.UTC)
    parameters = dict(request.query_params)
    if request.method == "POST":
        parameters.update({key: str(value) for key, value in (await request.form()).items()})

    relay_state = parameters.get("RelayState")

    # ------------------------------------------------ they're answering our request
    raw_response = parameters.get("SAMLResponse")
    if raw_response:
        state = (
            await session.scalar(
                select(SamlRequestState).where(SamlRequestState.relay_state == relay_state)
            )
            if relay_state
            else None
        )
        provider = (
            await session.scalar(
                select(IdentityProvider).where(IdentityProvider.slug == state.idp_slug)
            )
            if state is not None
            else None
        )

        if state is not None:
            await session.execute(
                delete(SamlRequestState).where(SamlRequestState.relay_state == state.relay_state)
            )

        confirmed = False
        if provider is not None:
            try:
                confirmation = read_logout_response(raw_response, provider.signing_cert)
                confirmed = confirmation.signature_verified and confirmation.succeeded
            except MalformedResponse:
                confirmed = False

        await session.commit()
        logger.info(
            "saml.single_logout_confirmed",
            extra={"idp": provider.slug if provider else None, "confirmed": confirmed},
        )

        # Home either way. Our session ended before the request went out, so a
        # provider that says no changes nothing on this side.
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        clear_session_cookie(response, settings=settings)
        return response

    # -------------------------------------------- they're telling us to sign someone out
    raw_request = parameters.get("SAMLRequest")
    if not raw_request:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="This endpoint expects a SAMLRequest or a SAMLResponse.",
        )

    identified = await _identify_logout_sender(session, raw_request, read_logout_request)
    if identified is None:
        await append_event(
            session,
            AuditDraft(
                action="saml.logout_request_refused",
                actor_type=ActorType.IDP,
                actor_label="Upstream IdP <unknown>",
                outcome=AuditOutcome.FAILURE,
                target_type="identity_provider",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                detail={
                    "reason": (
                        "the logout request was unsigned, or signed with a key no "
                        "registered provider holds, so there is no way to tell who "
                        "sent it"
                    )
                },
            ),
        )
        await session.commit()
        logger.warning("saml.logout_request_refused")
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="This logout request is not signed by a provider we know.",
        )

    provider, facts = identified

    ended = 0
    if facts.session_index:
        ended = await revoke_by_session_index(
            session,
            idp_slug=provider.slug,
            session_index=facts.session_index,
            now=now,
        )
    elif facts.name_id:
        # No session index: the provider means every session this person has with
        # us. That's what the spec says an absent index asks for, and it's the right
        # reading for "this account is gone".
        ended = await revoke_by_name_id(
            session,
            idp_slug=provider.slug,
            name_id=facts.name_id,
            reason=RevokedReason.SIGNED_OUT_ELSEWHERE,
            now=now,
        )

    await append_event(
        session,
        AuditDraft(
            action="saml.signed_out_elsewhere",
            actor_type=ActorType.IDP,
            actor_label=f"Upstream IdP <{provider.slug}>",
            outcome=AuditOutcome.SUCCESS,
            target_type="identity_provider",
            target_id=str(provider.id),
            target_label=provider.slug,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "request_id": facts.request_id,
                "session_index": facts.session_index,
                "sessions_ended": ended,
                "matched_on": "session_index" if facts.session_index else "name_id",
            },
        ),
    )
    await session.commit()

    logger.info(
        "saml.signed_out_elsewhere",
        extra={"idp": provider.slug, "sessions_ended": ended},
    )

    logout_response = build_logout_response(
        sp=sp,
        idp_slo_url=provider.slo_url or sp.slo_url,
        response_id=new_request_id(),
        in_response_to=facts.request_id,
        issued_at=now,
    )

    # Back to the provider if it gave us somewhere to answer, home otherwise. A
    # provider with no logout address that sends logout requests anyway is odd, but
    # dropping the person on a blank page over it would be worse.
    destination = (
        redirect_binding_url(
            provider.slo_url, saml_response=logout_response, relay_state=relay_state
        )
        if provider.slo_url
        else "/"
    )

    response = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response, settings=settings)
    return response
