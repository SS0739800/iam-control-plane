"""Tests for the login inspector.

The thing being checked is that a failed login leaves behind enough to work out
why. Not "it was refused" — which check, and what the values were. That is the
whole argument for doing the checks ourselves rather than calling one library
function, so it needs a test that would notice if the detail stopped being kept.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from tests.saml_harness import (
    POSTED_RESPONSE,
    ConsoleUsers,
    Scenario,
    StubReader,
    good_facts,
    post_login,
    seed_provider,
    seed_request,
)

pytestmark = pytest.mark.integration


def refuse_a_login(
    client: TestClient, scenario: Scenario, reader: StubReader, **broken: object
) -> None:
    """One login that fails, with exactly one thing wrong with it."""
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario, **broken)
    assert post_login(client, scenario).status_code in (400, 401, 403)


def accept_a_login(client: TestClient, scenario: Scenario, reader: StubReader) -> None:
    seed_provider(scenario)
    seed_request(scenario)
    reader.facts = good_facts(scenario)
    assert post_login(client, scenario).status_code == 303


def attempts(
    client: TestClient, console: ConsoleUsers, **params: str | int
) -> list[dict[str, object]]:
    """Read the inspector as an admin.

    The cookie has to go first. A test that just signed somebody in is holding
    their session, and a real session beats the development header every time —
    which is the behaviour we want, and it would otherwise make these requests
    come from a newly created employee with no permissions.
    """
    client.cookies.clear()
    response = client.get("/api/saml/logins", params=params, headers=console.as_admin)
    assert response.status_code == 200, response.text[:300]
    items: list[dict[str, object]] = response.json()["items"]
    return items


def mine(
    client: TestClient, console: ConsoleUsers, scenario: Scenario, **params: str | int
) -> dict[str, object]:
    """The most recent attempt for this test's provider."""
    found = [row for row in attempts(client, console, **params) if row["idp"] == scenario.idp_slug]
    assert found, "this test's login is not in the list"
    return found[0]


# ----------------------------------------------------------- a failed login


def test_a_failed_login_says_which_check_failed(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The point of the whole thing. "Invalid assertion" sends somebody hunting;
    "audience" tells them what to fix."""
    refuse_a_login(
        saml_client, scenario, saml_reader, audiences=("https://some-other-app.test/metadata",)
    )

    row = mine(saml_client, console, scenario)

    assert row["outcome"] == "failure"
    assert row["failed_checks"] == ["audience"]


def test_all_ten_results_are_kept_not_just_the_failures(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """A login that fails three checks means something different from one that
    fails a single one, and you can only tell if you have all the answers."""
    refuse_a_login(saml_client, scenario, saml_reader, signature_verified=False)

    row = mine(saml_client, console, scenario)
    checks = row["checks"]

    assert isinstance(checks, list)
    assert len(checks) == 10
    assert {check["name"] for check in checks} >= {
        "status",
        "signature",
        "assertion_signed",
        "issuer",
        "audience",
        "destination",
        "timing",
        "subject_confirmation",
        "in_response_to",
        "not_replayed",
    }


def test_each_result_says_why_in_words(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """The detail is the useful part. "timing: expired at 14:02, it is now 14:31"
    is an answer; a boolean is not."""
    refuse_a_login(saml_client, scenario, saml_reader, issuer="https://somebody-else.test")

    row = mine(saml_client, console, scenario)
    checks = row["checks"]
    assert isinstance(checks, list)
    issuer_check = next(check for check in checks if check["name"] == "issuer")

    assert issuer_check["passed"] is False
    assert "somebody-else" in issuer_check["detail"]


def test_a_failed_login_keeps_the_document_that_arrived(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """What you actually need when a provider starts sending something unexpected."""
    refuse_a_login(saml_client, scenario, saml_reader, signature_verified=False)

    row = mine(saml_client, console, scenario)
    assert row["has_response"] is True

    saml_client.cookies.clear()
    detail = saml_client.get(f"/api/saml/logins/{row['id']}", headers=console.as_admin)
    assert detail.status_code == 200
    assert detail.json()["decoded_response"] == base64.b64decode(POSTED_RESPONSE).decode(
        "utf-8", errors="replace"
    )


def test_a_login_that_could_not_be_read_at_all_is_still_listed(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """No checks ran, because there was nothing to check. It still has to show up,
    with the reason, or the failure is invisible."""
    from iam.saml.checks import MalformedResponse

    seed_provider(scenario)
    seed_request(scenario)
    saml_reader.error = MalformedResponse("response is not valid base64")
    assert post_login(saml_client, scenario).status_code == 400

    row = mine(saml_client, console, scenario)

    assert row["checks"] == []
    assert isinstance(row["reason"], str)
    assert "could not be read" in row["reason"]


# ---------------------------------------------------------- a good login


def test_a_successful_login_shows_what_it_did(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    accept_a_login(saml_client, scenario, saml_reader)

    row = mine(saml_client, console, scenario)

    assert row["outcome"] == "success"
    assert row["failed_checks"] == []
    assert row["session_id"]
    assert row["directory"] == "created on first login"
    assert scenario.user_name in str(row["who"])


def test_a_successful_login_does_not_keep_the_assertion(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Every check passed, so there is nothing to look at, and an assertion per
    login forever is a lot of somebody's personal data for no reason."""
    accept_a_login(saml_client, scenario, saml_reader)

    row = mine(saml_client, console, scenario)
    assert row["has_response"] is False

    saml_client.cookies.clear()
    detail = saml_client.get(f"/api/saml/logins/{row['id']}", headers=console.as_admin)
    assert detail.json()["decoded_response"] is None


# ------------------------------------------------------- listing and filtering


def test_only_failures_when_asked(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """Usually the only thing anybody wants from this screen."""
    accept_a_login(saml_client, scenario, saml_reader)

    rows = attempts(saml_client, console, outcome="failure")

    assert all(row["outcome"] == "failure" for row in rows)


def test_only_one_provider_when_asked(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    accept_a_login(saml_client, scenario, saml_reader)

    rows = attempts(saml_client, console, idp=scenario.idp_slug)

    assert rows
    assert all(row["idp"] == scenario.idp_slug for row in rows)


def test_ordinary_audit_entries_are_not_in_here(
    saml_client: TestClient, console: ConsoleUsers, scenario: Scenario, saml_reader: StubReader
) -> None:
    """It's a login inspector, not a second copy of the audit log. A user edit
    turning up here would make it useless for its one job."""
    accept_a_login(saml_client, scenario, saml_reader)

    rows = attempts(saml_client, console, limit=100)

    assert rows
    assert all(row["outcome"] in ("success", "failure") for row in rows)
    assert all(row["checks"] is not None for row in rows)


def test_an_entry_that_is_not_a_login_is_a_404(
    saml_client: TestClient, console: ConsoleUsers
) -> None:
    """Ids come from the audit log, so somebody could ask for any entry. Only the
    sign-in ones belong to this screen."""
    audit = saml_client.get(
        "/api/audit", params={"action": "user.created"}, headers=console.as_admin
    )
    entries = audit.json()["items"]
    if not entries:
        pytest.skip("no non-login audit entries in this database yet")

    response = saml_client.get(f"/api/saml/logins/{entries[0]['id']}", headers=console.as_admin)

    assert response.status_code == 404


def test_an_employee_cannot_read_it(saml_client: TestClient, console: ConsoleUsers) -> None:
    """Assertions carry other people's details. Reading them is the auditor's and
    the helpdesk's job, not everybody's."""
    response = saml_client.get("/api/saml/logins", headers=console.as_user(console.employee))

    assert response.status_code == 403


def test_an_auditor_can_read_it(saml_client: TestClient, console: ConsoleUsers) -> None:
    """Working out why somebody cannot sign in is exactly their job."""
    response = saml_client.get("/api/saml/logins", headers=console.as_user(console.auditor))

    assert response.status_code == 200
