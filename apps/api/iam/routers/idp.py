"""Being the identity provider: the endpoints applications talk to.

    /idp/metadata  the document you hand an application when registering it
    /idp/sso       where an application sends somebody to be signed in

The direction that makes this system an identity provider rather than a consumer
of one. Everything in P2 was us checking somebody else's word; here applications
take ours.

The rule that matters most
--------------------------

**The assertion is posted to the registered address, never to the one in the
request.** An AuthnRequest carries an ``AssertionConsumerServiceURL``, and honouring
it is the single worst mistake available on this endpoint. Anybody can send a
request naming a real application and their own return address; posting there would
hand an attacker a genuine signed assertion for whoever happened to be logged in.

So the request's copy is read, logged when it disagrees, and never used.

What has to be true before we sign anything
-------------------------------------------

Three things, in order, and each is a different refusal:

1. The application is registered and enabled. Otherwise we do not know where to
   send anything, and there is nothing to sign.
2. Somebody is signed in. If not they are sent to log in first and come back —
   which is the whole point of single sign-on.
3. That person has access to that application. This is where P4's entitlements stop
   being a reporting exercise and start being enforcement: an assertion is only
   issued to somebody an assignment says may have it.

Refusals after step one come back as SAML, not as an HTTP error page. Somebody
halfway through signing in to an application should land back at that application
with a reason, not stranded on our domain.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from typing import Annotated
from urllib.parse import urlencode
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep, SettingsDep
from iam.models.application import AppAssignment, Application
from iam.models.enums import ActorType, AppStatus, AuditOutcome
from iam.models.group import GroupMember
from iam.models.user import User
from iam.saml.checks import AuthnRequestFacts, MalformedResponse
from iam.saml.idp import (
    Issuer,
    LoginToIssue,
    SigningFailed,
    build_failure_response,
    build_response,
    new_session_index,
)
from iam.saml.keys import Keypair
from iam.security.actor import Actor, resolve_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/idp", tags=["identity provider"])

SAML_METADATA_MEDIA_TYPE = "application/samlmetadata+xml"

STATUS_REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
STATUS_REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

AuthnRequestReader = Callable[..., AuthnRequestFacts]


def _authn_request_reader() -> AuthnRequestReader:
    """The function that reads an application's login request.

    A dependency rather than an import, for the same two reasons as the SP side:
    reader.py needs xmlsec, which does not install on Windows, so importing it at
    module level would stop the app being importable on a laptop — and a test can
    swap in a reader returning prepared facts, which keeps every decision below
    covered outside the container.
    """
    from iam.saml.reader import read_authn_request

    return read_authn_request


AuthnRequestReaderDep = Annotated[AuthnRequestReader, Depends(_authn_request_reader)]


AssertionSigner = Callable[..., str]


def _assertion_signer() -> AssertionSigner:
    """The function that signs a finished response.

    The same seam as the reader above, and needed for the same reason: signer.py
    imports xmlsec through reader.py, so it cannot be imported on a laptop. Behind a
    dependency, everything this endpoint decides — registered, signed in, allowed —
    is covered by tests that run anywhere, and the signing itself is covered in the
    container by test_saml_signer.py.
    """
    from iam.saml.signer import sign_assertion

    return sign_assertion


AssertionSignerDep = Annotated[AssertionSigner, Depends(_assertion_signer)]


def _issuer(settings: SettingsDep) -> Issuer:
    return Issuer.from_base_url(settings.base_url)


IssuerDep = Annotated[Issuer, Depends(_issuer)]


def _keypair(request: Request) -> Keypair:
    """The signing keypair, loaded once when the app was built.

    On app.state rather than loaded here, so a missing or mismatched pair stops the
    process starting rather than failing the first login somebody tries.
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

    Not behind a login, the same as the SP metadata and for the same reason: it
    contains nothing secret, and requiring a session to fetch the document you need
    in order to set up signing in would be an awkward loop.
    """
    return Response(
        content=issuer.metadata_xml(certificate_body=keypair.certificate_body),
        media_type=SAML_METADATA_MEDIA_TYPE,
    )


def _attr(value: str) -> str:
    """Escape a value going into a double-quoted HTML attribute."""
    return escape(value, {'"': "&quot;"})


def _post_back(acs_url: str, saml_response: str, relay_state: str | None) -> HTMLResponse:
    """The auto-submitting form that carries the response to the application.

    SAML's POST binding has no other shape: the browser has to make a cross-site
    POST, and only a form can. The submit button matters — it is what somebody sees
    if scripting is off, and without it they are stuck on a blank page with no way
    to continue.
    """

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("ascii")

    # Both of the values below land inside a double-quoted HTML attribute, so the
    # quote needs escaping as well as the usual three. Neither is ours: RelayState
    # is opaque data the application chose, and the ACS URL was typed into a form by
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

    Directly, or through a group they are in. This is the moment P4's entitlements
    stop being a report and become enforcement — everything else in this system
    records who should have access, and this is the one place that acts on it.
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

    Deliberately small. Every attribute here is one more thing an application starts
    depending on, and one more thing that has to keep being true — so this is the
    set an application actually needs to identify somebody and place them, and
    nothing more.

    Group names are included because that is how an application does its own
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

    Posted back to the application rather than rendered here. Somebody halfway
    through signing in should end up at the application they were going to, with
    something it can explain — not on our domain looking at an error.
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
    application: Application,
    user: User,
    in_response_to: str | None,
    relay_state: str | None,
) -> HTMLResponse:
    """Sign somebody in to an application, and record it."""
    acs_url = application.acs_url or ""
    session_index = new_session_index()

    login = LoginToIssue(
        # The person's own id, not their email. Emails change; this does not, and an
        # application keying its records on something that changes is how somebody
        # ends up with two accounts after they get married.
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
        # application anyway, and sending one would put the confusing error at their
        # end rather than ours.
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
                # Named rather than valued: an audit entry is not the place to
                # duplicate somebody's personal details, and which attributes were
                # released is the reviewable fact.
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

    Looked up rather than believed. The entity id in an AuthnRequest is a claim
    about who is asking, and this is the step that turns it into either a row we
    trust or a refusal.
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

    Also handles a login we start ourselves: with ``?app=slug`` and no SAMLRequest,
    somebody clicking an application in the console gets signed straight in. That is
    what an application calls IdP-initiated, and it is legal — the assertion simply
    carries no InResponseTo.
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
        # A request that arrived by POST and is coming back through here after a
        # login was never deflated. See _login_url_returning_here.
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

    Offered because our metadata says we offer it, and an application that reads
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

    Rebuilt rather than taken from ``request.url``, because of the POST binding. A
    login is a redirect, a redirect is a GET, and the body of the POST that started
    this does not survive it — so the request travels back in the query string
    instead, and ``binding=post`` says the payload is base64 that was never deflated.
    Without that it would come back as an unreadable request, and an application
    whose users happen to be signed in already would work while the same application
    failed for everybody else.

    Everything is encoded properly. The old form pasted the query on unencoded, which
    made the ampersands in it read as parameters of /saml/login rather than as part
    of where to return to — so a login request with a RelayState came back without one.
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
            # No readable request means no issuer, so no application, so nowhere to
            # post a SAML failure to. This is the one refusal that has to be an HTTP
            # error, because there is no address to send anything else to.
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
        # Still an HTTP error, and for the same reason: without a registered
        # application there is no trusted address to post a failure to. Using the
        # one from the request here is exactly the mistake this endpoint refuses to
        # make.
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

    # Read, logged, and not used. See the module docstring: honouring this is how an
    # attacker gets a genuine signed assertion delivered to a server they chose.
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

    # Are they signed in? Two different answers come back from resolve_actor and they
    # mean opposite things here, so the exception is read rather than swallowed. 401
    # is "nobody is signed in", which is the ordinary case at the start of single
    # sign-on and means send them to log in and come back. 403 is "we know exactly
    # who this is and their account is switched off", and sending them to log in
    # would be a loop with no exit — that one is a refusal the application is told
    # about. Anything else is a fault at our end and is not turned into a login page.
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
        # A backstop rather than the main path — resolve_actor refuses a deactivated
        # account above. It stays because the check that matters least is the one
        # that catches the case nobody predicted, and issuing an assertion for
        # somebody who has left is not a mistake worth making twice.
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
        # The point where P4 stops being a report. Somebody signed in, at a real
        # application, refused because nothing grants them access to it.
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

    Exists so the console can offer "open this application" without anybody
    constructing a query string, and so a bookmark to an application is a normal
    looking URL.
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
