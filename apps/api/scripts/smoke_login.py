"""Drive a whole SAML login against the running stack, with no browser.

    python -m scripts.smoke_login

Starts at /saml/login, authenticates against authentik, takes the assertion it
hands back and posts it to /saml/acs, then uses the resulting session cookie on
/api/me and signs out again.

Needs the whole stack up, authentik included, and authentik registered as a
provider:

    docker compose --profile idp up -d
    curl -sSL http://localhost:9000/application/saml/iam-console/metadata/ -o idp.xml
    # then POST it to /api/identity-providers — see the README

This exists because CI cannot do it. There is no identity provider in CI, so the
one thing no test there can check is whether a real assertion from a real provider
is accepted. That gap is not theoretical: the xpath bug fixed in
iam/saml/reader.py passed every unit test and failed the first time a genuine
authentik assertion arrived.

authentik drives its own login pages from an API: a browser GETs a flow page, the
front end asks the executor for a "challenge", posts an answer, and gets the next
challenge. This walks the same executor, which is why no browser is needed. It is
therefore tied to authentik's flow API, and an authentik upgrade is the thing most
likely to break it.
"""

from __future__ import annotations

import os
import pathlib
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

CONSOLE = "http://localhost:8080"
AUTHENTIK = "http://localhost:9000"
USERNAME = "akadmin"
PASSWORD = os.environ.get("AUTHENTIK_BOOTSTRAP_PASSWORD", "dev-only-authentik-admin-password")

MAX_STAGES = 12


def step(message: str) -> None:
    print(f"\n=== {message}")


class Idp:
    """Walks authentik's flow executor the way its own front end does."""

    def __init__(self) -> None:
        self.http = httpx.Client(base_url=AUTHENTIK, follow_redirects=True, timeout=30)

    def _flow_at(self, url: str) -> tuple[str, str]:
        """Follow a browser-facing URL to the flow page it lands on."""
        landed = self.http.get(url)
        assert landed.status_code == 200, f"HTTP {landed.status_code}: {landed.text[:300]}"
        parsed = urlparse(str(landed.url))
        slug = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        return slug, parsed.query

    def _challenge(self, slug: str, query: str) -> dict[str, Any]:
        response = self.http.get(f"/api/v3/flows/executor/{slug}/", params={"query": query})
        assert response.status_code == 200, f"HTTP {response.status_code}: {response.text[:300]}"
        body: dict[str, Any] = response.json()
        return body

    def _answer(self, slug: str, query: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.http.post(
            f"/api/v3/flows/executor/{slug}/",
            params={"query": query},
            json=payload,
            headers={
                "X-authentik-CSRF": self.http.cookies.get("authentik_csrf") or "",
                "Referer": AUTHENTIK,
            },
        )
        assert response.status_code == 200, f"HTTP {response.status_code}: {response.text[:300]}"
        body: dict[str, Any] = response.json()
        return body

    def sign_in_and_collect_assertion(self, sso_url: str) -> dict[str, str]:
        """Log in, and return the form fields authentik wants posted to our ACS."""
        slug, query = self._flow_at(sso_url)
        print(f"  flow: {slug}")
        assert "next" in parse_qs(query), f"the SAML request was dropped: {query[:200]}"

        challenge = self._challenge(slug, query)

        for _ in range(MAX_STAGES):
            component = challenge.get("component")
            print(f"  stage: {component}")

            if component == "ak-stage-autosubmit":
                # The end of it: the form a browser would submit for you.
                attrs = challenge.get("attrs") or {}
                print(f"  posts to: {challenge.get('url')}")
                return {str(k): str(v) for k, v in attrs.items()}

            if component == "xak-flow-redirect":
                # Off to another flow — the authorization one, which is where the
                # assertion gets built.
                slug, query = self._flow_at(str(challenge["to"]))
                print(f"  flow: {slug}")
                challenge = self._challenge(slug, query)
                continue

            if component == "ak-stage-identification":
                challenge = self._answer(
                    slug, query, {"component": component, "uid_field": USERNAME}
                )
                continue

            if component == "ak-stage-password":
                challenge = self._answer(
                    slug, query, {"component": component, "password": PASSWORD}
                )
                continue

            if component == "ak-stage-access-denied":
                raise AssertionError(f"authentik refused the login: {challenge}")

            # Consent, "you're already signed in", and friends: submit empty.
            challenge = self._answer(slug, query, {"component": component})

        raise AssertionError("authentik's flow never produced an assertion")


def main() -> int:
    console = httpx.Client(base_url=CONSOLE, follow_redirects=False, timeout=30)
    idp = Idp()

    step("1. start at /saml/login")
    started = console.get("/saml/login", params={"idp": "authentik", "return_to": "/users"})
    print(f"HTTP {started.status_code}")
    assert started.status_code == 303, started.text[:400]
    sso_url = started.headers["location"]
    print(f"  sent to {urlparse(sso_url).path}")

    step("2. authenticate at authentik and collect the assertion")
    fields = idp.sign_in_and_collect_assertion(sso_url)
    assert "SAMLResponse" in fields, fields
    print(f"  SAMLResponse: {len(fields['SAMLResponse'])} chars")
    print(f"  RelayState:   {fields.get('RelayState', '(none)')[:24]}…")

    # Somewhere to save the assertion, for use as a test fixture. That is where
    # tests/fixtures/authentik-response.b64 came from.
    dump_to = os.environ.get("DUMP_ASSERTION")
    if dump_to:
        pathlib.Path(dump_to).write_text(fields["SAMLResponse"], encoding="utf-8")
        print(f"  saved the assertion to {dump_to}")

    step("3. post it to /saml/acs — real xmlsec signature check happens here")
    accepted = console.post("/saml/acs", data=fields)
    print(f"HTTP {accepted.status_code}")
    if accepted.status_code != 303:
        print(accepted.text[:1200])
        return 1
    print(f"  redirected to {accepted.headers['location']}")
    print(f"  session cookie set: {bool(accepted.cookies.get('iam_session'))}")

    step("4. use the session on /api/me")
    # Naming a user who does not exist, so the development stand-in cannot be what
    # answers this. A 200 here means the cookie did it.
    who = console.get("/api/me", headers={"X-Dev-Actor": "nobody@demo.local"})
    print(f"HTTP {who.status_code}")
    print(f"  {who.text}")
    assert who.status_code == 200, who.text[:400]
    assert who.json()["via_saml_session"] is True

    step("5. sign out, and check the cookie stops working")
    console.post("/saml/logout")
    after = console.get("/api/me", headers={"X-Dev-Actor": "nobody@demo.local"})
    print(f"/api/me after signing out: HTTP {after.status_code}")
    assert after.status_code == 401

    print("\nThe whole loop works, signature check included.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
