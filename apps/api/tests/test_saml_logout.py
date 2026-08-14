"""Tests for being recognised by the session cookie, and for signing out.

The round trip is the point: log in, get recognised as the person who logged in,
sign out, stop being recognised. Testing those separately would miss the thing
that actually breaks, which is one of them not talking to the other.

These need Postgres and skip without IAM_TEST_DATABASE_URL. They do not need
xmlsec — see tests/saml_harness.py for what stands in for it and what doesn't.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.saml import SamlSession
from iam.saml.sessions import SESSION_IDLE_TIMEOUT, RevokedReason
from tests.saml_harness import (
    Scenario,
    StubReader,
    deactivate_user,
    fetch_session,
    good_facts,
    post_login,
    run_db,
    seed_request,
    sign_in,
)

pytestmark = pytest.mark.integration

# The development stand-in would answer for any request without a cookie, which
# would make every test below pass whether the cookie worked or not.
NOBODY = {"X-Dev-Actor": "nobody-with-this-name@demo.local"}


def age_the_session(scenario: Scenario, by: dt.timedelta) -> None:
    """Backdate a session's last-seen time, to test the idle timeout without waiting."""
    stored = fetch_session(scenario)
    assert stored is not None
    session_id = stored.id
    last_seen = stored.last_seen_at

    async def work(session: AsyncSession) -> None:
        await session.execute(
            update(SamlSession)
            .where(SamlSession.id == session_id)
            .values(last_seen_at=last_seen - by)
        )

    run_db(work)


# ------------------------------------------------ being recognised by the cookie


def test_the_cookie_from_a_login_identifies_the_person(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    sign_in(saml_client, scenario, saml_reader)

    who = saml_client.get("/api/me", headers=NOBODY)

    assert who.status_code == 200
    assert who.json()["user_name"] == scenario.user_name
    assert who.json()["via_saml_session"] is True


def test_the_cookie_wins_over_the_development_header(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """A real session must never be overridden or downgraded by the stand-in.

    Without this, the stand-in would be a way to impersonate somebody else while
    signed in as yourself, which is worse than it being a way in at all.
    """
    sign_in(saml_client, scenario, saml_reader)

    who = saml_client.get("/api/me", headers={"X-Dev-Actor": "admin@demo.local"})

    assert who.status_code == 200
    assert who.json()["user_name"] == scenario.user_name


def test_a_made_up_cookie_does_not_identify_anybody(
    saml_client: TestClient, scenario: Scenario
) -> None:
    saml_client.cookies.set("iam_session", "a-token-nobody-ever-issued")

    who = saml_client.get("/api/me", headers=NOBODY)

    assert who.status_code == 401


def test_a_session_left_idle_stops_being_accepted(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Still inside its eight hours, but nothing has happened on it for an hour."""
    sign_in(saml_client, scenario, saml_reader)
    age_the_session(scenario, SESSION_IDLE_TIMEOUT + dt.timedelta(minutes=1))

    who = saml_client.get("/api/me", headers=NOBODY)

    assert who.status_code == 401


def test_using_a_session_keeps_it_from_going_idle(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The last-seen time only gets rewritten once it has actually gone stale, so
    this backdates it past that threshold first."""
    sign_in(saml_client, scenario, saml_reader)
    age_the_session(scenario, dt.timedelta(minutes=30))
    before = fetch_session(scenario)
    assert before is not None

    saml_client.get("/api/me", headers=NOBODY)

    after = fetch_session(scenario)
    assert after is not None
    assert after.last_seen_at > before.last_seen_at


def test_deactivating_somebody_cuts_off_the_session_they_are_using(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The moment we notice. This is what P4's leaver flow depends on."""
    sign_in(saml_client, scenario, saml_reader)
    deactivate_user(scenario)

    who = saml_client.get("/api/me", headers=NOBODY)

    assert who.status_code == 403
    assert "deactivated" in who.json()["detail"]

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_reason == RevokedReason.USER_DEACTIVATED


# ------------------------------------------------------------- signing out


def test_signing_out_ends_the_session(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    sign_in(saml_client, scenario, saml_reader)

    response = saml_client.post("/saml/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_at is not None
    assert ended.revoked_reason == RevokedReason.SIGNED_OUT


def test_signing_out_clears_the_cookie(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    sign_in(saml_client, scenario, saml_reader)

    response = saml_client.post("/saml/logout", follow_redirects=False)

    assert "iam_session=" in response.headers["set-cookie"]
    assert saml_client.cookies.get("iam_session") in (None, "")


def test_after_signing_out_the_cookie_no_longer_works(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The one that matters. Clearing the cookie alone would leave a live session
    for anyone who kept a copy of the token.
    """
    sign_in(saml_client, scenario, saml_reader)
    stolen = saml_client.cookies["iam_session"]

    saml_client.post("/saml/logout", follow_redirects=False)

    saml_client.cookies.set("iam_session", stolen)
    who = saml_client.get("/api/me", headers=NOBODY)

    assert who.status_code == 401


def test_signing_out_records_it(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Marked, not deleted, so "signed out at 14:32" stays answerable."""
    sign_in(saml_client, scenario, saml_reader)

    saml_client.post("/saml/logout", follow_redirects=False)

    ended = fetch_session(scenario)
    assert ended is not None
    assert ended.revoked_at is not None


def test_signing_out_twice_is_harmless(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """ "You were already signed out" is a technically accurate and useless error."""
    sign_in(saml_client, scenario, saml_reader)

    first = saml_client.post("/saml/logout", follow_redirects=False)
    second = saml_client.post("/saml/logout", follow_redirects=False)

    assert first.status_code == 303
    assert second.status_code == 303


def test_signing_out_without_ever_signing_in_is_harmless(saml_client: TestClient) -> None:
    response = saml_client.post("/saml/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_signing_out_ends_one_session_not_all_of_them(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Signing out on your phone must not sign you out on your laptop.

    Cutting all of somebody's sessions at once is a different operation with a
    different reason attached, and it belongs to P4's leaver flow.
    """
    sign_in(saml_client, scenario, saml_reader)
    laptop = saml_client.cookies["iam_session"]

    # Log in a second time, as if from another device. Fresh request and fresh
    # assertion id, or it would be turned away as a replay.
    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    saml_reader.facts = good_facts(
        scenario,
        assertion_id=f"{scenario.assertion_id}-2",
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
    )
    post_login(saml_client, scenario, relay_state=f"{scenario.relay_state}-2")
    phone = saml_client.cookies["iam_session"]
    assert phone != laptop

    saml_client.post("/saml/logout", follow_redirects=False)

    saml_client.cookies.set("iam_session", laptop)
    assert saml_client.get("/api/me", headers=NOBODY).status_code == 200

    saml_client.cookies.set("iam_session", phone)
    assert saml_client.get("/api/me", headers=NOBODY).status_code == 401
