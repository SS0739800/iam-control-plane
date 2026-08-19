"""Tests for POST /saml/acs, the endpoint that accepts a login.

These need Postgres, because refusing a login writes an audit entry and accepting
one writes a person and a session. They skip without IAM_TEST_DATABASE_URL, and
CI sets it.

They do not need xmlsec. The shared harness in tests/saml_harness.py explains
what stands in for it and, more importantly, what does not: every decision below
is the real code. The stub only replaces "read this XML and verify it".
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient

from iam.models.enums import IdentitySource
from iam.saml.checks import MalformedResponse
from iam.saml.sp import REQUEST_TTL
from iam.tokens import hash_token
from tests.saml_harness import (
    STUB_CERT,
    Scenario,
    StubReader,
    deactivate_user,
    fetch_session,
    fetch_user,
    good_facts,
    post_login,
    seed_provider,
    seed_request,
)

pytestmark = pytest.mark.integration


# ------------------------------------------------- logins we never asked for


def test_a_login_with_no_relay_state_is_refused(
    saml_client: TestClient, scenario: Scenario
) -> None:
    """Nothing ties it to a request we sent, so there is nothing to check it
    against. This is the shape of a login posted at us out of the blue."""
    response = post_login(saml_client, scenario, relay_state="")

    assert response.status_code == 400
    assert "RelayState" in response.json()["detail"]


def test_a_login_we_have_no_record_of_is_refused(
    saml_client: TestClient, scenario: Scenario
) -> None:
    response = post_login(saml_client, scenario, relay_state="a-token-we-never-issued")

    assert response.status_code == 400
    assert "no record" in response.json()["detail"]


def test_an_expired_request_is_refused(saml_client: TestClient, scenario: Scenario) -> None:
    """Ten minutes is enough to type a password. An hour later, no."""
    seed_provider(scenario)
    seed_request(scenario, age=REQUEST_TTL + dt.timedelta(minutes=1))

    response = post_login(saml_client, scenario)

    assert response.status_code == 400
    assert "expired" in response.json()["detail"]


def test_a_provider_turned_off_mid_login_is_refused(
    saml_client: TestClient, scenario: Scenario
) -> None:
    seed_provider(scenario, enabled=False)
    seed_request(scenario)

    response = post_login(saml_client, scenario)

    assert response.status_code == 400
    assert "turned off" in response.json()["detail"]


def test_a_login_that_cannot_be_read_is_refused(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """A 400, not a 401. There was nothing to check, which is different from
    checking it and not liking the answer."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.error = MalformedResponse("response is not valid base64")

    response = post_login(saml_client, scenario)

    assert response.status_code == 400
    assert "could not be read" in response.json()["detail"]


# --------------------------------------------------------- failing the checks


def test_a_login_from_the_wrong_provider_is_refused(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario, issuer="https://somebody-else.test")

    response = post_login(saml_client, scenario)

    assert response.status_code == 401
    assert "issuer" in response.json()["detail"]


def test_a_login_meant_for_another_application_is_refused(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Without this, anybody with an account on that other application becomes a
    user here."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(
        scenario, audiences=("https://some-other-app.test/saml/metadata",)
    )

    response = post_login(saml_client, scenario)

    assert response.status_code == 401
    assert "audience" in response.json()["detail"]


def test_an_unsigned_login_is_refused(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario, signature_verified=False)

    response = post_login(saml_client, scenario)

    assert response.status_code == 401
    assert "signature" in response.json()["detail"]
    assert fetch_user(scenario) is None


def test_a_login_answering_a_different_request_is_refused(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The relay state was ours but the id inside wasn't."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(
        scenario, in_response_to="id-something-else", subject_in_response_to="id-something-else"
    )

    response = post_login(saml_client, scenario)

    assert response.status_code == 401
    assert "in_response_to" in response.json()["detail"]


def test_the_provider_certificate_is_the_one_we_stored(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The whole basis of trust. Verifying against anything else is verifying
    nothing."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)

    post_login(saml_client, scenario)

    assert saml_reader.certs_seen == [STUB_CERT]


def test_a_refused_login_still_consumes_the_request(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """One answer per request, right or wrong.

    Leave the request open after a failure and a captured login can be retried
    until something lines up. This is the test that says it can't be.
    """
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario, issuer="https://somebody-else.test")

    first = post_login(saml_client, scenario)
    saml_reader.facts = good_facts(scenario)
    second = post_login(saml_client, scenario)

    assert first.status_code == 401
    assert second.status_code == 400
    assert "no record" in second.json()["detail"]


# ------------------------------------------------------------- a good login


def test_a_good_login_signs_the_person_in(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario, return_to="/users")
    saml_reader.facts = good_facts(scenario)

    response = post_login(saml_client, scenario)

    assert response.status_code == 303
    assert response.headers["location"] == "/users"


def test_a_good_login_sets_a_locked_down_cookie(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """httponly so a scripting bug can't read it, samesite so another site can't
    ride on it. Lax rather than strict, or the person lands back here still
    looking logged out."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)

    response = post_login(saml_client, scenario)

    set_cookie = response.headers["set-cookie"]
    assert "iam_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("samesite", "SameSite")
    assert "Path=/" in set_cookie


def test_the_cookie_value_is_not_what_gets_stored(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Only the hash is written down, the same way passwords are handled. Someone
    who reads the sessions table still can't sign in as anybody."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)

    response = post_login(saml_client, scenario)
    token = response.cookies["iam_session"]

    stored = fetch_session(scenario)
    assert stored is not None
    assert stored.token_hash == hash_token(token)
    assert stored.token_hash != token


def test_a_good_login_records_what_the_provider_called_the_session(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Needed later so "they signed out over there" can be matched to a session
    here."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)

    post_login(saml_client, scenario)

    stored = fetch_session(scenario)
    assert stored is not None
    assert stored.session_index == f"session-index-{scenario.suffix}"
    assert stored.name_id == f"persistent-{scenario.suffix}"


def test_a_first_login_creates_the_person(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)

    post_login(saml_client, scenario)

    created = fetch_user(scenario)
    assert created is not None
    assert created.display_name == "Ada Bergman"
    assert created.source is IdentitySource.JIT


def test_an_unsafe_return_path_falls_back_to_the_home_page(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Checked on the way in as well. This is the second look, so a tampered-with
    row can't turn a successful login into a redirect to somebody else's site."""
    seed_provider(scenario)
    seed_request(scenario, return_to="//evil.example")
    saml_reader.facts = good_facts(scenario)

    response = post_login(saml_client, scenario)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_a_deactivated_person_cannot_log_in(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The provider will happily sign someone in who we've switched off. Ours is
    the answer that counts, and P4 leans on this holding."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)
    post_login(saml_client, scenario)

    deactivate_user(scenario)

    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    saml_reader.facts = good_facts(
        scenario,
        assertion_id=f"{scenario.assertion_id}-2",
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
    )
    response = post_login(saml_client, scenario, relay_state=f"{scenario.relay_state}-2")

    assert response.status_code == 403
    assert "deactivated" in response.json()["detail"]


def test_the_same_login_cannot_be_used_twice(
    saml_client: TestClient, scenario: Scenario, saml_reader: StubReader
) -> None:
    """A captured login is otherwise good until it expires. Note this needs a
    second request state to get past the one-answer-per-request rule, which is
    exactly the situation replay protection exists for: everything else about the
    second attempt is fine."""
    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.facts = good_facts(scenario)
    first = post_login(saml_client, scenario)

    seed_request(
        scenario, relay_state=f"{scenario.relay_state}-2", request_id=f"{scenario.request_id}-2"
    )
    saml_reader.facts = good_facts(
        scenario,
        in_response_to=f"{scenario.request_id}-2",
        subject_in_response_to=f"{scenario.request_id}-2",
    )
    second = post_login(saml_client, scenario, relay_state=f"{scenario.relay_state}-2")

    assert first.status_code == 303
    assert second.status_code == 401
    assert "not_replayed" in second.json()["detail"]
