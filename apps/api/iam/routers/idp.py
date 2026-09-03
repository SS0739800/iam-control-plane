"""Being the identity provider: the endpoints applications talk to.

    /idp/metadata  the document you hand an application when registering it
    /idp/sso       where an application sends somebody to be signed in
    /idp/slo       where an application tells us somebody signed out

The direction that makes this system an identity provider rather than a
consumer of one. Everything in P2 was us checking somebody else's word; here
applications take ours.

The rule that matters most: the assertion is posted to the registered
address, never to the one in the request. An AuthnRequest carries an
``AssertionConsumerServiceURL``, and honouring it is the worst mistake
available on this endpoint — anybody can send a request naming a real
application and their own return address, and posting there would hand an
attacker a genuine signed assertion for whoever happened to be logged in. So
the request's copy is read, logged when it disagrees, and never used.

Three things have to be true before we sign anything, in order, each a
different refusal:

1. The application is registered and enabled. Otherwise there's nowhere to
   send anything, and nothing to sign.
2. Somebody is signed in. If not, they're sent to log in first and come
   back — the whole point of single sign-on.
3. That person has access to that application. This is where P4's
   entitlements stop being a reporting exercise and start being enforcement:
   an assertion is only issued to somebody an assignment says may have it.

Refusals after step one come back as SAML, not an HTTP error page. Somebody
halfway through signing in to an application should land back at that
application with a reason, not stranded on our domain.
"""

from __future__ import annotations

import base64
import datetime as dt
import logging
import zlib
from collections.abc import Callable
from typing import Annotated
from urllib.parse import urlencode
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.deps import SessionDep, SettingsDep
from iam.models.application import AppAssignment, Application
from iam.models.enums import ActorType, AppStatus, AuditOutcome
from iam.models.group import GroupMember
from iam.models.idp_session import IdpSession
from iam.models.saml import SamlSession
from iam.models.user import User
from iam.saml.checks import AuthnRequestFacts, LogoutRequestFacts, MalformedResponse
from iam.saml.idp import (
    Issuer,
    LoginToIssue,
    SigningFailed,
    build_failure_response,
    build_logout_response,
    build_response,
    new_session_index,
)
from iam.saml.keys import Keypair
from iam.saml.sessions import RevokedReason, lookup_session, revoke_all_for_user
from iam.security.actor import Actor, resolve_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/idp", tags=["identity provider"])

SAML_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"

STATUS_REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
STATUS_REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

AuthnRequestReader = Callable[..., AuthnRequestFacts]


def _authn_request_reader() -> AuthnRequestReader:
    """The function that reads an application's login request.

    A dependency rather than an import, for the same two reasons as the SP
    side: reader.py needs xmlsec, which doesn't install on Windows, so
    importing it at module level would stop the app being importable on a
    laptop — and a test can swap in a reader returning prepared facts, which
    keeps every decision below covered outside the container.
    """
    from iam.saml.reader import read_authn_request

    return read_authn_request


AuthnRequestReaderDep = Annotated[AuthnRequestReader, Depends(_authn_request_reader)]


AssertionSigner = Callable[..., str]


def _assertion_signer() -> AssertionSigner:
    """The function that signs a finished response.

    Same seam as the reader above, and same reason: signer.py imports xmlsec
    through reader.py, so it can't be imported on a laptop. Behind a
    dependency, everything this endpoint decides — registered, signed in,
    allowed — is covered by tests that run anywhere, and the signing itself
    is covered in the container by test_saml_signer.py.
    """
    from iam.saml.signer import sign_assertion

    return sign_assertion


AssertionSignerDep = Annotated[AssertionSigner, Depends(_assertion_signer)]


DocumentSigner = Callable[..., str]


def _document_signer() -> DocumentSigner:
    """The function that signs a document with no assertion in it.

    Kept separate from the assertion signer — see sign_document in signer.py
    for why the two shouldn't be one function with a flag.
    """
    from iam.saml.signer import sign_document

    return sign_document


DocumentSignerDep = Annotated[DocumentSigner, Depends(_document_signer)]


LogoutRequestReader = Callable[..., LogoutRequestFacts]


def _logout_request_reader() -> LogoutRequestReader:
    """The function that reads an application's logout request.

    Same seam as the other two, for the same reason: reader.py needs xmlsec.
    """
    from iam.saml.reader import read_logout_request

    return read_logout_request


LogoutRequestReaderDep = Annotated[LogoutRequestReader, Depends(_logout_request_reader)]


def _issuer(settings: SettingsDep) -> Issuer:
    return Issuer.from_base_url(settings.base_url)


IssuerDep = Annotated[Issuer, Depends(_issuer)]


def _keypair(request: Request) -> Keypair:
    """The signing keypair, loaded once when the app was built.

    On app.state rather than loaded here, so a missing or mismatched pair
    stops the process starting rather than failing the first login somebody
    tries.
    """
    keypair: Keypair = request.app.state.saml_keypair
    return keypair


KeypairDep = Annotated[Keypair, Depends(_keypair)]


@router.get(
    "/metadata",
    summary="Our details, for registering an application against this system",
    response_class=Response,
    responses={200: {"content": {SAML_METADATA_MEDIA_TYPE: {}}}},
)
async def metadata(issuer: IssuerDep, keypair: KeypairDep) -> Response:
    """Hand this to whoever is setting up an application.

    Not behind a login, same as the SP metadata and for the same reason: it
    contains nothing secret, and requiring a session to fetch the document
    you need to set up signing in would be a loop.
    """
    return Response(
        content=issuer.metadata_xml(certificate_body=keypair.certificate_body),
        media_type=SAML_METADATA_MEDIA_TYPE,
    )


async def current_saml_session(
    db: SessionDep, request: Request, settings: Settings
) -> SamlSession | None:
    """The browser session this request came from, if there is one.

    Recorded against every login we issue so a logout can be traced back to
    the browser. Returns nothing for a request identified by the development
    stand-in, which has no session cookie behind it — that's a real gap, and
    it means such a login can only be matched by subject.
    """
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    return await lookup_session(db, token, now=dt.datetime.now(dt.UTC))


def _attr(value: str) -> str:
    """Escape a value going into a double-quoted HTML attribute."""
    return escape(value, {'"': "&quot;"})


def _post_back(acs_url: str, saml_response: str, relay_state: str | None) -> HTMLResponse:
    """The auto-submitting form that carries the response to the application.

    SAML's POST binding has no other shape: the browser has to make a
    cross-site POST, and only a form can. The submit button matters: it's
    what somebody sees if scripting is off, and without it they're stuck on
    a blank page with no way to continue.
    """

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("ascii")

    # Both values below land inside a double-quoted HTML attribute, so the
    # quote needs escaping too. Neither is ours: RelayState is opaque data
    # the application chose, and the ACS URL was typed into a form by
    # whoever registered it.
    relay = (
        f'    <input type="hidden" name="RelayState" value="{_attr(relay_state)}"/>\n'
        if relay_state
        else ""
    )

    return HTMLResponse(
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head><title>Signing you in…</title></head>\n"
        '<body onload="document.forms[0].submit()">\n'
        "  <p>Signing you in…</p>\n"
        f'  <form method="post" action="{escape(acs_url, {chr(34): "&quot;"})}">\n'
        f'    <input type="hidden" name="SAMLResponse" value="{encoded}"/>\n'
        f"{relay}"
        '    <noscript><button type="submit">Continue</button></noscript>\n'
        "  </form>\n"
        "</body>\n"
        "</html>\n"
    )


async def _has_access(session: SessionDep, user: User, application: Application) -> bool:
    """Whether this person may sign in to this application.

    Directly, or through a group they're in. This is the moment P4's
    entitlements stop being a report and become enforcement — everything
    else in this system records who should have access, this is the one
    place that acts on it.
    """
    direct = await session.scalar(
        select(AppAssignment.id).where(
            AppAssignment.application_id == application.id,
            AppAssignment.user_id == user.id,
        )
    )
    if direct is not None:
        return True

    via_group = await session.scalar(
        select(AppAssignment.id)
        .join(GroupMember, GroupMember.group_id == AppAssignment.group_id)
        .where(
            AppAssignment.application_id == application.id,
            GroupMember.user_id == user.id,
        )
    )
    return via_group is not None


async def _attributes_for(session: SessionDep, user: User) -> dict[str, list[str]]:
    """What we tell the application about this person.

    Kept small. Every attribute here is one more thing an application
    starts depending on, so this is the set an application actually needs
    to identify somebody and place them, and nothing more.

    Group names are included since that's how an application does its own
    authorisation without asking us a second time.
    """
    from iam.models.group import Group

    groups = (
        await session.scalars(
            select(Group.name)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user.id)
            .order_by(Group.name)
        )
    ).all()

    attributes: dict[str, list[str]] = {
        "email": [user.email],
        "userName": [user.user_name],
        "displayName": [user.display_name],
    }
    if user.given_name:
        attributes["givenName"] = [user.given_name]
    if user.family_name:
        attributes["surname"] = [user.family_name]
    if user.department:
        attributes["department"] = [user.department]
    if groups:
        attributes["groups"] = list(groups)

    return attributes


async def _refuse(
    session: SessionDep,
    request: Request,
    *,
    issuer: Issuer,
    acs_url: str,
    in_response_to: str | None,
    relay_state: str | None,
    status_code: str,
    message: str,
    application: Application | None,
    actor_label: str,
    detail: dict[str, object],
) -> HTMLResponse:
    """Say no, in SAML, and write down why.

    Posted back to the application rather than rendered here. Somebody
    halfway through signing in should end up at the application they were
    going to, with something it can explain — not stuck on our domain
    looking at an error.
    """
    await append_event(
        session,
        AuditDraft(
            action="idp.login_refused",
            actor_type=ActorType.USER,
            actor_label=actor_label,
            outcome=AuditOutcome.DENIED,
            target_type="application",
            target_id=str(application.id) if application else None,
            target_label=application.slug if application else None,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": message, **detail},
        ),
    )
    await session.commit()

    logger.warning("idp.login_refused", extra={"reason": message, **detail})

    return _post_back(
        acs_url,
        build_failure_response(
            issuer=issuer,
            acs_url=acs_url,
            in_response_to=in_response_to,
            status_code=status_code,
            message=message,
        ),
        relay_state,
    )


async def _issue(
    session: SessionDep,
    request: Request,
    *,
    issuer: Issuer,
    keypair: Keypair,
    sign: AssertionSigner,
    settings: Settings,
    application: Application,
    user: User,
    in_response_to: str | None,
    relay_state: str | None,
) -> HTMLResponse:
    """Sign somebody in to an application, and record it."""
    acs_url = application.acs_url or ""
    session_index = new_session_index()

    login = LoginToIssue(
        # The person's own id, not their email. Emails change and this
        # doesn't; an application keying its records on something that
        # changes is how somebody ends up with two accounts.
        name_id=str(user.id),
        audience=application.entity_id or "",
        acs_url=acs_url,
        in_response_to=in_response_to,
        session_index=session_index,
        attributes=await _attributes_for(session, user),
    )

    unsigned = build_response(login, issuer=issuer)

    try:
        signed = sign(
            unsigned,
            private_key_pem=keypair.private_key_pem,
            certificate_pem=keypair.certificate_pem,
        )
    except SigningFailed as exc:
        # Nothing usable to send: an unsigned assertion is rejected by the
        # application anyway, and sending one would put the confusing error
        # at their end rather than ours.
        logger.error(
            "idp.signing_failed",
            extra={"application": application.slug, "error": str(exc)},
        )
        return await _refuse(
            session,
            request,
            issuer=issuer,
            acs_url=acs_url,
            in_response_to=in_response_to,
            relay_state=relay_state,
            status_code=STATUS_REQUEST_UNSUPPORTED,
            message="This login could not be signed. Nothing is wrong at your end.",
            application=application,
            actor_label=f"{user.display_name} <{user.user_name}>",
            detail={"error": str(exc)},
        )

    # Written before the audit entry — this is the row that makes single
    # logout possible. The SessionIndex above went out in the assertion; an
    # application asking us to sign the person out quotes it back, and
    # without this row there'd be nothing to match it against. See
    # iam/models/idp_session.py.
    #
    # The browser session is recorded when there is one. A login issued
    # through the development stand-in has no session cookie behind it, so
    # this is nullable rather than refusing the flow — but a logout for it
    # can only be matched by subject, not by browser.
    signed_in_session = await current_saml_session(session, request, settings)
    session.add(
        IdpSession(
            saml_session_id=signed_in_session.id if signed_in_session else None,
            user_id=user.id,
            application_id=application.id,
            session_index=session_index,
            name_id=login.name_id,
            issued_at=login.issued_at,
        )
    )

    await append_event(
        session,
        AuditDraft(
            action="idp.login_issued",
            actor_type=ActorType.USER,
            actor_id=user.id,
            actor_label=f"{user.display_name} <{user.user_name}>",
            outcome=AuditOutcome.SUCCESS,
            target_type="application",
            target_id=str(application.id),
            target_label=application.slug,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "audience": application.entity_id,
                "acs_url": acs_url,
                "session_index": session_index,
                "in_response_to": in_response_to,
                # Named rather than valued: an audit entry isn't the place to
                # duplicate somebody's personal details, and which
                # attributes were released is the reviewable fact.
                "attributes_released": sorted(login.attributes),
            },
        ),
    )
    await session.commit()

    logger.info(
        "idp.login_issued",
        extra={"application": application.slug, "user": user.user_name},
    )

    return _post_back(acs_url, signed, relay_state)


async def _application_for(session: SessionDep, entity_id: str) -> Application | None:
    """The registered application with this entity id, if it is switched on.

    Looked up rather than believed. The entity id in an AuthnRequest is a
    claim about who is asking; this is the step that turns it into either a
    row we trust or a refusal.
    """
    found: Application | None = await session.scalar(
        select(Application).where(
            Application.entity_id == entity_id,
            Application.status == AppStatus.ACTIVE,
        )
    )
    return found


@router.get("/sso", summary="Sign somebody in to an application")
async def sso_redirect(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    issuer: IssuerDep,
    keypair: KeypairDep,
    sign: AssertionSignerDep,
    read_request: AuthnRequestReaderDep,
    saml_request: Annotated[str | None, Query(alias="SAMLRequest")] = None,
    relay_state: Annotated[str | None, Query(alias="RelayState")] = None,
    app_slug: Annotated[str | None, Query(alias="app")] = None,
    binding: Annotated[
        str | None,
        Query(
            description=(
                "Ours, not SAML's. Set to 'post' only on the way back from logging "
                "in, to say the request came in by POST and so is not deflated."
            )
        ),
    ] = None,
) -> Response:
    """The redirect binding, and the one most applications use.

    Also handles a login we start ourselves: with ``?app=slug`` and no
    SAMLRequest, somebody clicking an application in the console gets
    signed straight in. That's what an application calls IdP-initiated,
    and it's legal — the assertion simply carries no InResponseTo.
    """
    return await _sign_in(
        request,
        session,
        settings,
        issuer=issuer,
        keypair=keypair,
        sign=sign,
        read_request=read_request,
        saml_request=saml_request,
        relay_state=relay_state,
        app_slug=app_slug,
        # A request that arrived by POST and is coming back through here
        # after a login was never deflated. See _login_url_returning_here.
        deflated=binding != "post",
    )


@router.post("/sso", summary="Sign somebody in to an application (POST binding)")
async def sso_post(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    issuer: IssuerDep,
    keypair: KeypairDep,
    sign: AssertionSignerDep,
    read_request: AuthnRequestReaderDep,
    saml_request: Annotated[str | None, Form(alias="SAMLRequest")] = None,
    relay_state: Annotated[str | None, Form(alias="RelayState")] = None,
) -> Response:
    """The POST binding. Same decisions, different envelope.

    Offered because our metadata says we offer it; an application that reads
    metadata and then finds only one binding working has been lied to.
    """
    return await _sign_in(
        request,
        session,
        settings,
        issuer=issuer,
        keypair=keypair,
        sign=sign,
        read_request=read_request,
        saml_request=saml_request,
        relay_state=relay_state,
        app_slug=None,
        deflated=False,
    )


def _login_url_returning_here(
    *,
    saml_request: str | None,
    relay_state: str | None,
    app_slug: str | None,
    deflated: bool,
) -> str:
    """Where to send somebody who has to log in first, and how they get back.

    Rebuilt rather than taken from ``request.url``, because of the POST
    binding. A login is a redirect, a redirect is a GET, and the body of the
    POST that started this doesn't survive it — so the request travels back
    in the query string instead, and ``binding=post`` says the payload is
    base64 that was never deflated. Without that it would come back as an
    unreadable request, working only for users who happened to already be
    signed in.

    Everything is encoded properly. The old form pasted the query on
    unencoded, which made its ampersands read as parameters of /saml/login
    instead of part of where to return to — so a login request with a
    RelayState came back without one.
    """
    returning: dict[str, str] = {}
    if saml_request:
        returning["SAMLRequest"] = saml_request
        if not deflated:
            returning["binding"] = "post"
    if relay_state:
        returning["RelayState"] = relay_state
    if app_slug:
        returning["app"] = app_slug

    return_to = "/idp/sso"
    if returning:
        return_to = f"{return_to}?{urlencode(returning)}"

    return f"/saml/login?{urlencode({'return_to': return_to})}"


async def _sign_in(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    *,
    issuer: Issuer,
    keypair: Keypair,
    sign: AssertionSigner,
    read_request: AuthnRequestReader,
    saml_request: str | None,
    relay_state: str | None,
    app_slug: str | None,
    deflated: bool,
) -> Response:
    """Everything both bindings do, which is everything that matters."""
    facts: AuthnRequestFacts | None = None
    application: Application | None = None

    if saml_request:
        try:
            facts = read_request(saml_request, None, deflated=deflated)
        except MalformedResponse as exc:
            # No readable request means no issuer, so no application, so
            # nowhere to post a SAML failure to. This has to be an HTTP
            # error since there's no other address to send anything to.
            logger.warning("idp.unreadable_request", extra={"error": str(exc)})
            return Response(
                content=f"That login request could not be read: {exc}",
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="text/plain",
            )

        application = await _application_for(session, facts.issuer)

    elif app_slug:
        application = await session.scalar(
            select(Application).where(
                Application.slug == app_slug, Application.status == AppStatus.ACTIVE
            )
        )

    if application is None or not application.acs_url or not application.entity_id:
        # Still an HTTP error, same reason: without a registered application
        # there's no trusted address to post a failure to. Using the one
        # from the request here is the exact mistake this endpoint refuses
        # to make.
        named = facts.issuer if facts else (app_slug or "nothing")
        logger.warning("idp.unknown_application", extra={"requested": named})
        return Response(
            content=(
                f"No application is registered here as {named!r}, or it has no "
                "assertion consumer address. Register it first."
            ),
            status_code=status.HTTP_404_NOT_FOUND,
            media_type="text/plain",
        )

    # Read, logged, and not used. See the module docstring: honouring this
    # is how an attacker gets a genuine signed assertion delivered to a
    # server they chose.
    if facts and facts.acs_url and facts.acs_url != application.acs_url:
        logger.warning(
            "idp.acs_url_ignored",
            extra={
                "application": application.slug,
                "asked_for": facts.acs_url,
                "using": application.acs_url,
            },
        )

    in_response_to = facts.request_id if facts else None

    # Are they signed in? Two different answers come back from resolve_actor
    # and they mean opposite things here, so the exception is read rather
    # than swallowed. 401 is "nobody is signed in", the ordinary case at the
    # start of single sign-on, meaning send them to log in and come back.
    # 403 is "we know exactly who this is and their account is switched
    # off", where sending them to log in would be a loop with no exit —
    # that's a refusal the application gets told about. Anything else is a
    # fault at our end and isn't turned into a login page.
    try:
        actor: Actor = await resolve_actor(request, session, settings)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return RedirectResponse(
                url=_login_url_returning_here(
                    saml_request=saml_request,
                    relay_state=relay_state,
                    app_slug=app_slug,
                    deflated=deflated,
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        return await _refuse(
            session,
            request,
            issuer=issuer,
            acs_url=application.acs_url,
            in_response_to=in_response_to,
            relay_state=relay_state,
            status_code=STATUS_REQUEST_DENIED,
            message="That account is not active.",
            application=application,
            actor_label="somebody whose account is switched off",
            detail={"status_code": exc.status_code},
        )

    user = await session.get(User, actor.user_id)
    if user is None or not user.active:
        # A backstop, not the main path — resolve_actor refuses a
        # deactivated account above. Kept because issuing an assertion for
        # somebody who's left isn't a mistake worth making twice.
        return await _refuse(
            session,
            request,
            issuer=issuer,
            acs_url=application.acs_url,
            in_response_to=in_response_to,
            relay_state=relay_state,
            status_code=STATUS_REQUEST_DENIED,
            message="That account is not active.",
            application=application,
            actor_label=actor.audit_label,
            detail={"user_name": actor.user_name},
        )

    if not await _has_access(session, user, application):
        # The point where P4 stops being a report. Somebody signed in, at a
        # real application, refused because nothing grants them access.
        return await _refuse(
            session,
            request,
            issuer=issuer,
            acs_url=application.acs_url,
            in_response_to=in_response_to,
            relay_state=relay_state,
            status_code=STATUS_REQUEST_DENIED,
            message=f"You do not have access to {application.name}.",
            application=application,
            actor_label=actor.audit_label,
            detail={"user_name": user.user_name, "application": application.slug},
        )

    return await _issue(
        session,
        request,
        settings=settings,
        issuer=issuer,
        keypair=keypair,
        sign=sign,
        application=application,
        user=user,
        in_response_to=in_response_to,
        relay_state=relay_state,
    )


@router.get("/sso/{app_slug}", summary="Sign in to an application by name")
async def sso_for_app(
    app_slug: str,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    issuer: IssuerDep,
    keypair: KeypairDep,
    sign: AssertionSignerDep,
    read_request: AuthnRequestReaderDep,
) -> Response:
    """A tidy link for a login we start ourselves.

    Exists so the console can offer "open this application" without
    anybody constructing a query string, and so a bookmark to an
    application looks like a normal URL.
    """
    return await _sign_in(
        request,
        session,
        settings,
        issuer=issuer,
        keypair=keypair,
        sign=sign,
        read_request=read_request,
        saml_request=None,
        relay_state=None,
        app_slug=app_slug,
        deflated=True,
    )


# ------------------------------------------------------------- single logout


async def _end_idp_session(
    session: SessionDep, found: IdpSession, *, reason: str, now: dt.datetime
) -> None:
    """Mark one application login as finished."""
    found.ended_at = now
    found.ended_reason = reason
    await session.flush()


async def _resolve_logout_target(
    session: SessionDep, facts: LogoutRequestFacts
) -> IdpSession | None:
    """Find the login an application is asking us to end.

    By session index first, since that one is ours and exact: we issued it,
    it's unique, and it names one login at one application.

    By subject second, since a request is allowed to name only the NameID.
    That's looser, so it's narrowed to logins still open at the application
    that asked — without that narrowing, a request from one application
    could close somebody's login at another, which isn't its business.
    """
    if facts.session_index:
        by_index: IdpSession | None = await session.scalar(
            select(IdpSession).where(IdpSession.session_index == facts.session_index)
        )
        if by_index is not None:
            return by_index

    if facts.name_id:
        application = await _application_for(session, facts.issuer)
        if application is None:
            return None
        by_subject: IdpSession | None = await session.scalar(
            select(IdpSession)
            .where(
                IdpSession.name_id == facts.name_id,
                IdpSession.application_id == application.id,
                IdpSession.ended_at.is_(None),
            )
            .order_by(IdpSession.issued_at.desc())
        )
        return by_subject

    return None


@router.get("/slo", summary="An application telling us somebody signed out")
async def slo_redirect(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    issuer: IssuerDep,
    keypair: KeypairDep,
    sign_document: DocumentSignerDep,
    read_logout: LogoutRequestReaderDep,
    saml_request: Annotated[str | None, Query(alias="SAMLRequest")] = None,
    relay_state: Annotated[str | None, Query(alias="RelayState")] = None,
) -> Response:
    """The redirect binding, which is what our metadata advertises.

    This address was in the metadata before it was in the code: we
    published a document promising an endpoint that answered 404.

    It couldn't just be written either. See iam/models/idp_session.py — the
    SessionIndex we put in every assertion was generated fresh and never
    stored, so a logout request quoting one had nothing to match against.
    """
    return await _sign_out(
        request,
        session,
        settings,
        issuer=issuer,
        keypair=keypair,
        sign_document=sign_document,
        read_logout=read_logout,
        saml_request=saml_request,
        relay_state=relay_state,
        deflated=True,
    )


@router.post("/slo", summary="An application telling us somebody signed out (POST binding)")
async def slo_post(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    issuer: IssuerDep,
    keypair: KeypairDep,
    sign_document: DocumentSignerDep,
    read_logout: LogoutRequestReaderDep,
    saml_request: Annotated[str | None, Form(alias="SAMLRequest")] = None,
    relay_state: Annotated[str | None, Form(alias="RelayState")] = None,
) -> Response:
    """The POST binding. Same decisions, different envelope."""
    return await _sign_out(
        request,
        session,
        settings,
        issuer=issuer,
        keypair=keypair,
        sign_document=sign_document,
        read_logout=read_logout,
        saml_request=saml_request,
        relay_state=relay_state,
        deflated=False,
    )


async def _sign_out(
    request: Request,
    session: SessionDep,
    settings: Settings,
    *,
    issuer: Issuer,
    keypair: Keypair,
    sign_document: DocumentSigner,
    read_logout: LogoutRequestReader,
    saml_request: str | None,
    relay_state: str | None,
    deflated: bool,
) -> Response:
    """End a login an application asked us to end, and confirm it.

    It ends our record of that application's login, and it ends the browser
    session the login came from, so the person is signed out of this
    console too — what somebody clicking "log out" at an application means.

    It does not notify the other applications that person is signed into.
    That's single logout's fan-out: the table this reads makes it possible
    for the first time (one browser session, several rows, each naming an
    address to tell), but the fan-out itself isn't built yet. So the honest
    description of this endpoint is "single-application logout, plus
    ending the console session", and the audit entry says so rather than
    leaving it implied.
    """
    now = dt.datetime.now(dt.UTC)

    if not saml_request:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="No SAMLRequest. This endpoint answers logout requests from applications.",
        )

    try:
        facts = read_logout(saml_request, None, deflated=deflated)
    except MalformedResponse as exc:
        # Nothing readable means no issuer, so nowhere to send a
        # LogoutResponse. An HTTP error is all that's left.
        logger.warning("idp.unreadable_logout_request", extra={"error": str(exc)})
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"That logout request could not be read: {exc}",
        ) from exc

    application = await _application_for(session, facts.issuer)
    if application is None or not application.slo_url:
        logger.warning(
            "idp.logout_from_unknown_application",
            extra={"issuer": facts.issuer, "registered": application is not None},
        )
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=(
                f"No application is registered here as {facts.issuer!r}, or it has no "
                "logout address to reply to."
            ),
        )

    target = await _resolve_logout_target(session, facts)

    console_session_ended = False
    if target is not None:
        await _end_idp_session(session, target, reason="application_signed_out", now=now)

        # And the browser session behind it. Somebody clicking log out at an
        # application means to be signed out — leaving them signed in here
        # would let one click take them straight back in with no password.
        if target.saml_session_id is not None:
            ended = await revoke_all_for_user(
                session,
                target.user_id,
                reason=RevokedReason.SIGNED_OUT_ELSEWHERE,
                now=now,
            )
            console_session_ended = bool(ended)

    await append_event(
        session,
        AuditDraft(
            action="idp.logout_received",
            actor_type=ActorType.IDP if target is None else ActorType.USER,
            actor_id=target.user_id if target else None,
            actor_label=(
                f"{application.name} signed out "
                f"{facts.name_id or facts.session_index or 'somebody'}"
            ),
            outcome=AuditOutcome.SUCCESS,
            target_type="application",
            target_id=str(application.id),
            target_label=application.slug,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={
                "session_index": facts.session_index,
                "name_id": facts.name_id,
                "matched": target is not None,
                "console_session_ended": console_session_ended,
                # Recorded so the gap is visible in the log, not only in a
                # docstring. Anybody auditing a logout should see that the
                # other applications weren't told.
                "other_applications_notified": False,
            },
        ),
    )
    await session.commit()

    logger.info(
        "idp.logout_received",
        extra={
            "application": application.slug,
            "matched": target is not None,
            "console_session_ended": console_session_ended,
        },
    )

    unsigned = build_logout_response(
        issuer=issuer,
        destination=application.slo_url,
        in_response_to=facts.request_id,
        issued_at=now,
        # Success even when nothing matched. The application asked for the
        # person to be signed out and they are — see build_logout_response.
        success=True,
    )

    try:
        signed = sign_document(
            unsigned,
            private_key_pem=keypair.private_key_pem,
            certificate_pem=keypair.certificate_pem,
        )
    except SigningFailed as exc:
        logger.error("idp.logout_signing_failed", extra={"error": str(exc)})
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The logout confirmation could not be signed.",
        ) from exc

    return _redirect_back(application.slo_url, signed, relay_state)


def _redirect_back(slo_url: str, logout_response: str, relay_state: str | None) -> RedirectResponse:
    """Send the confirmation back over the redirect binding.

    Deflated and base64 in a query string, per the binding and what our
    metadata says we use.
    """
    deflater = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    packed = deflater.compress(logout_response.encode("utf-8")) + deflater.flush()

    query: dict[str, str] = {"SAMLResponse": base64.b64encode(packed).decode("ascii")}
    if relay_state:
        query["RelayState"] = relay_state

    separator = "&" if "?" in slo_url else "?"
    return RedirectResponse(
        url=f"{slo_url}{separator}{urlencode(query)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
