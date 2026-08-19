"""Point this system at itself: our identity provider signing us into our own console.

    python -m scripts.smoke_selfloop

Registers our own IdP metadata as a provider, our own SP metadata as an
application, then drives one login all the way round:

    /saml/login  ->  /idp/sso  ->  signed assertion  ->  /saml/acs  ->  a session

Why this is worth having
------------------------

It is the strongest end-to-end check available without a public hostname, because
the two halves were written four phases apart against the specification rather than
against each other. P2 reads and validates assertions; P5 builds and signs them.
Neither was written with the other in mind.

So this exercises, in one pass and for real: building an AuthnRequest, reading one,
looking the application up by entity id, checking the person has access to it,
building the assertion, signing it with xmlsec, verifying that signature, all ten
checks in checks.py, replay protection, and issuing a session cookie. A failure
anywhere in that chain shows up here as a refusal with a reason.

It also demonstrates something a single-sided test cannot: that what we publish is
acceptable to a real service provider, because ours is one.

What it is not
--------------

Not a substitute for smoke_login.py. That one proves a *third party* accepts what we
ask for and that we accept what it sends — a loop can agree with itself about
something both halves get wrong. Run both.

Needs the stack up. Does not need authentik.
"""

from __future__ import annotations

import re
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

CONSOLE = "http://localhost:8080"

PROVIDER_SLUG = "self"
APPLICATION_SLUG = "self-console"

# The console's own admin, who has to end up with access to the application.
ACTOR = "admin@demo.local"


def step(message: str) -> None:
    print(f"\n=== {message}")


def detail(message: str) -> None:
    print(f"    {message}")


def fail(message: str) -> int:
    print(f"\nFAILED: {message}")
    return 1


def register_ourselves_as_a_provider(client: httpx.Client) -> None:
    """Trust our own signing certificate, the way any provider is trusted.

    Nothing special happens here. It is the ordinary registration path, reading the
    ordinary metadata document — which is the point: if our published metadata were
    not real metadata, this step would refuse it.
    """
    metadata = client.get(f"{CONSOLE}/idp/metadata")
    metadata.raise_for_status()

    response = client.post(
        f"{CONSOLE}/api/identity-providers",
        json={
            "slug": PROVIDER_SLUG,
            "name": "This console, acting as its own provider",
            "metadata_xml": metadata.text,
        },
        headers={"X-Dev-Actor": ACTOR},
    )
    response.raise_for_status()
    detail(f"provider {PROVIDER_SLUG!r} -> {response.json()['sso_url']}")


def register_ourselves_as_an_application(client: httpx.Client) -> str:
    """Register our own assertion consumer as somewhere we issue logins to."""
    metadata = client.get(f"{CONSOLE}/saml/metadata")
    metadata.raise_for_status()

    response = client.post(
        f"{CONSOLE}/api/applications",
        json={
            "slug": APPLICATION_SLUG,
            "name": "This console, acting as its own application",
            "description": "Registered by scripts.smoke_selfloop.",
            "metadata_xml": metadata.text,
        },
        headers={"X-Dev-Actor": ACTOR},
    )
    response.raise_for_status()
    body: dict[str, Any] = response.json()
    detail(f"application {APPLICATION_SLUG!r} -> {body['acs_url']}")
    app_id: str = body["id"]
    return app_id


def grant_access(client: httpx.Client, app_id: str) -> None:
    """Give the admin access to it.

    Without this the login is refused, and that refusal is itself worth seeing: it
    is P4's entitlements deciding a P5 question.
    """
    users = client.get(
        f"{CONSOLE}/api/users", params={"q": ACTOR}, headers={"X-Dev-Actor": ACTOR}
    )
    users.raise_for_status()
    items = users.json()["items"]
    if not items:
        raise RuntimeError(f"{ACTOR} does not exist. Has the seed script run?")

    response = client.put(
        f"{CONSOLE}/api/applications/{app_id}/users/{items[0]['id']}",
        json={"role": "Admin"},
        headers={"X-Dev-Actor": ACTOR},
    )
    if response.status_code not in (200, 201, 204, 409):
        response.raise_for_status()
    detail(f"{ACTOR} may use it")


def start_the_login(client: httpx.Client) -> str:
    """Ask our own service provider to begin, and get the redirect to our own IdP."""
    response = client.get(
        f"{CONSOLE}/saml/login",
        params={"idp": PROVIDER_SLUG, "return_to": "/api/me"},
        follow_redirects=False,
    )
    if response.status_code != 303:
        raise RuntimeError(f"expected a redirect to the provider, got {response.status_code}")

    location = response.headers["location"]
    query = parse_qs(urlparse(location).query)
    detail(f"redirected to {urlparse(location).path}")
    detail(f"carrying a request of {len(query.get('SAMLRequest', [''])[0])} characters")
    return location


def collect_the_assertion(client: httpx.Client, sso_url: str) -> tuple[str, str | None]:
    """Follow the redirect to our own IdP and take the assertion out of the form.

    The IdP answers with an auto-submitting form, because SAML's POST binding has no
    other shape. A browser would submit it; this reads the fields out instead.
    """
    response = client.get(sso_url, headers={"X-Dev-Actor": ACTOR}, follow_redirects=False)
    if response.status_code != 200:
        raise RuntimeError(
            f"the provider answered {response.status_code}, not a form: {response.text[:200]}"
        )

    found = re.search(r'name="SAMLResponse" value="([^"]+)"', response.text)
    if not found:
        raise RuntimeError(f"no SAMLResponse in the form: {response.text[:300]}")

    relay = re.search(r'name="RelayState" value="([^"]+)"', response.text)
    action = re.search(r'action="([^"]+)"', response.text)

    detail(f"posting back to {action.group(1) if action else 'unknown'}")
    detail(f"assertion is {len(found.group(1))} characters, signed")
    return found.group(1), relay.group(1) if relay else None


def deliver_the_assertion(
    client: httpx.Client, saml_response: str, relay_state: str | None
) -> httpx.Response:
    """Post it to our own assertion consumer, as the browser would.

    Everything after this point is P2 code that has never seen a P5 document.
    """
    form = {"SAMLResponse": saml_response}
    if relay_state:
        form["RelayState"] = relay_state

    return client.post(f"{CONSOLE}/saml/acs", data=form, follow_redirects=False)


def main() -> int:
    with httpx.Client(timeout=30.0) as client:
        try:
            step("Trusting our own certificate, as a provider")
            register_ourselves_as_a_provider(client)

            step("Registering our own console as an application")
            app_id = register_ourselves_as_an_application(client)

            step("Granting access to it")
            grant_access(client, app_id)

            step("Starting a login at our own service provider")
            sso_url = start_the_login(client)

            step("Our identity provider signs an assertion")
            saml_response, relay_state = collect_the_assertion(client, sso_url)

            step("Our service provider reads it back and runs all ten checks")
            landed = deliver_the_assertion(client, saml_response, relay_state)
        except (httpx.HTTPError, RuntimeError) as exc:
            return fail(str(exc))

        if landed.status_code != 303:
            body = landed.text[:400]
            return fail(
                f"the assertion was refused with {landed.status_code}. This is the "
                f"interesting failure — the two halves disagree about something:\n\n{body}"
            )

        detail(f"accepted, landing at {landed.headers.get('location')}")

        cookie = landed.cookies.get("iam_session") or client.cookies.get("iam_session")
        if not cookie:
            return fail("no session cookie was set, so the login did not really happen")
        detail("session cookie set")

        step("Using the session it issued")
        me = client.get(f"{CONSOLE}/api/me", cookies={"iam_session": cookie})
        if me.status_code != 200:
            return fail(f"/api/me answered {me.status_code} with that cookie")

        who = me.json()
        detail(f"signed in as {who['user_name']} ({who['role']})")
        detail(f"via a real SAML session: {who['via_saml_session']}")

        if not who["via_saml_session"]:
            return fail(
                "the session did not come from SAML, so something answered with the "
                "development stand-in instead"
            )

        step("Replaying the same assertion, which must be refused")
        again = deliver_the_assertion(client, saml_response, relay_state)
        if again.status_code == 303:
            return fail("the same assertion was accepted twice — replay protection is not working")
        detail(f"refused with {again.status_code}, as it should be")

    print("\nThe loop closed. Our own provider signed a login our own consumer accepted.")
    print("Both halves were written four phases apart, against the spec, not each other.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
