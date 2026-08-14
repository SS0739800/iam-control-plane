"""Tests for the login checks.

One test per way a login can be wrong. Each one starts from a login that would be
accepted, breaks exactly one thing, and confirms that the matching check fails and
the login is rejected.

That shape matters. A test that feeds in something wrong in five ways and asserts
"rejected" passes even if four of the five checks were deleted.

No xmlsec here, so these run anywhere.
"""

from __future__ import annotations

import datetime as dt

import pytest

from iam.saml.checks import (
    SAML_SUCCESS,
    AssertionFacts,
    Expectations,
    all_passed,
    check_assertion_signed,
    check_audience,
    check_destination,
    check_in_response_to,
    check_issuer,
    check_not_replayed,
    check_signature,
    check_status,
    check_subject_confirmation,
    check_timing,
    failed_names,
    run_all_checks,
)

NOW = dt.datetime(2026, 8, 14, 12, 0, 0, tzinfo=dt.UTC)

OUR_ENTITY_ID = "https://iam.demo.local/saml/metadata"
OUR_ACS_URL = "https://iam.demo.local/saml/acs"
IDP_ENTITY_ID = "https://authentik.demo.local"
REQUEST_ID = "id-request-0001"


def good_facts(**overrides: object) -> AssertionFacts:
    """A login that should be accepted. Tests override one field at a time."""
    defaults: dict[str, object] = {
        "assertion_id": "id-assertion-abc",
        "issuer": IDP_ENTITY_ID,
        "status_code": SAML_SUCCESS,
        "audiences": (OUR_ENTITY_ID,),
        "destination": OUR_ACS_URL,
        "in_response_to": REQUEST_ID,
        "not_before": NOW - dt.timedelta(minutes=1),
        "not_on_or_after": NOW + dt.timedelta(minutes=5),
        "subject_not_on_or_after": NOW + dt.timedelta(minutes=5),
        "subject_recipient": OUR_ACS_URL,
        "subject_in_response_to": REQUEST_ID,
        "name_id": "ada.bergman@demo.local",
        "signature_verified": True,
        "assertion_was_signed": True,
    }
    defaults.update(overrides)
    return AssertionFacts(**defaults)  # type: ignore[arg-type]


def expectations(**overrides: object) -> Expectations:
    defaults: dict[str, object] = {
        "our_entity_id": OUR_ENTITY_ID,
        "our_acs_url": OUR_ACS_URL,
        "idp_entity_id": IDP_ENTITY_ID,
        "expected_request_id": REQUEST_ID,
    }
    defaults.update(overrides)
    return Expectations(**defaults)  # type: ignore[arg-type]


# --------------------------------------------------------------- the happy path


def test_a_good_login_passes_everything() -> None:
    results = run_all_checks(good_facts(), expectations(), now=NOW, already_seen=False)

    assert all_passed(results), failed_names(results)
    assert len(results) == 10, "every check should report, even on success"


def test_every_check_reports_a_result() -> None:
    """The inspector shows all of them, so all of them have to come back named."""
    results = run_all_checks(good_facts(), expectations(), now=NOW, already_seen=False)

    assert [r.name for r in results] == [
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
    ]


def test_a_failure_does_not_stop_the_other_checks() -> None:
    """Being able to tell "one thing wrong" from "everything wrong" depends on this."""
    facts = good_facts(signature_verified=False, audiences=("https://someone-else",))

    results = run_all_checks(facts, expectations(), now=NOW, already_seen=False)

    assert len(results) == 10
    assert set(failed_names(results)) == {"signature", "audience"}


# ------------------------------------------------------------ one break at a time


def test_rejects_a_login_the_provider_said_failed() -> None:
    facts = good_facts(status_code="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")

    assert not check_status(facts).passed
    assert "AuthnFailed" in check_status(facts).detail


def test_rejects_an_unsigned_or_wrongly_signed_login() -> None:
    assert not check_signature(good_facts(signature_verified=False)).passed


def test_rejects_a_login_where_only_the_wrapper_was_signed() -> None:
    """Signing the envelope but not the contents leaves the contents swappable."""
    facts = good_facts(assertion_was_signed=False)

    assert not check_assertion_signed(facts, expectations()).passed


def test_allows_an_unsigned_assertion_when_the_provider_cannot_sign_one() -> None:
    facts = good_facts(assertion_was_signed=False)

    result = check_assertion_signed(facts, expectations(require_signed_assertion=False))

    assert result.passed
    assert "not required" in result.detail


def test_rejects_a_login_from_an_unknown_provider() -> None:
    facts = good_facts(issuer="https://attacker.example")

    result = check_issuer(facts, expectations())

    assert not result.passed
    assert "attacker.example" in result.detail


def test_rejects_a_login_meant_for_a_different_application() -> None:
    """This is the one that matters most. Without it, anyone with an account on
    another app that shares our provider can get in here."""
    facts = good_facts(audiences=("https://some-other-app.example",))

    result = check_audience(facts, expectations())

    assert not result.passed
    assert "some-other-app" in result.detail


def test_rejects_a_login_addressed_to_nobody() -> None:
    assert not check_audience(good_facts(audiences=()), expectations()).passed


def test_rejects_a_login_sent_somewhere_else() -> None:
    facts = good_facts(destination="https://another-app.example/saml/acs")

    assert not check_destination(facts, expectations()).passed


def test_allows_a_missing_destination() -> None:
    """The spec permits leaving it out, so its absence is not a failure."""
    assert check_destination(good_facts(destination=None), expectations()).passed


def test_ignores_a_trailing_slash_difference_in_the_destination() -> None:
    """Providers are inconsistent about this and it isn't a real mismatch."""
    facts = good_facts(destination=OUR_ACS_URL + "/")

    assert check_destination(facts, expectations()).passed


def test_rejects_an_expired_login() -> None:
    facts = good_facts(not_on_or_after=NOW - dt.timedelta(hours=1))

    result = check_timing(facts, expectations(), NOW)

    assert not result.passed
    assert "expired" in result.detail


def test_rejects_a_login_dated_in_the_future() -> None:
    facts = good_facts(not_before=NOW + dt.timedelta(hours=1))

    result = check_timing(facts, expectations(), NOW)

    assert not result.passed
    assert "not valid until" in result.detail


@pytest.mark.parametrize("drift_seconds", [-100, -30, 0, 30, 100])
def test_tolerates_small_clock_differences(drift_seconds: int) -> None:
    """A provider whose clock is a minute out should still work."""
    drifted = NOW + dt.timedelta(seconds=drift_seconds)
    facts = good_facts(
        not_before=drifted - dt.timedelta(seconds=5),
        not_on_or_after=drifted + dt.timedelta(seconds=5),
    )

    assert check_timing(facts, expectations(), NOW).passed


def test_does_not_tolerate_a_wildly_wrong_clock() -> None:
    """Slack has to stay small, or an expired login keeps working."""
    facts = good_facts(not_on_or_after=NOW - dt.timedelta(minutes=30))

    assert not check_timing(facts, expectations(), NOW).passed


def test_rejects_a_login_whose_subject_window_has_closed() -> None:
    facts = good_facts(subject_not_on_or_after=NOW - dt.timedelta(minutes=10))

    assert not check_subject_confirmation(facts, expectations(), NOW).passed


def test_rejects_a_login_whose_subject_names_someone_else_as_recipient() -> None:
    facts = good_facts(subject_recipient="https://another-app.example/saml/acs")

    result = check_subject_confirmation(facts, expectations(), NOW)

    assert not result.passed
    assert "another-app" in result.detail


def test_rejects_a_login_we_never_asked_for() -> None:
    """An unprompted login that looks valid is the shape of the attack."""
    facts = good_facts(in_response_to=None, subject_in_response_to=None)

    result = check_in_response_to(facts, expectations())

    assert not result.passed
    assert REQUEST_ID in result.detail


def test_rejects_a_login_answering_a_different_request() -> None:
    facts = good_facts(in_response_to="id-some-other-request", subject_in_response_to=None)

    assert not check_in_response_to(facts, expectations()).passed


def test_allows_a_provider_initiated_login_when_we_were_not_waiting() -> None:
    """Clicking the app from the provider's own portal is legitimate."""
    facts = good_facts(in_response_to=None, subject_in_response_to=None)

    result = check_in_response_to(facts, expectations(expected_request_id=None))

    assert result.passed
    assert "provider-initiated" in result.detail


def test_rejects_a_login_quoting_a_request_we_never_sent() -> None:
    facts = good_facts(in_response_to="id-made-up")

    assert not check_in_response_to(facts, expectations(expected_request_id=None)).passed


def test_falls_back_to_the_subject_when_the_response_omits_the_request_id() -> None:
    """Some providers only put it on the subject. Both places are valid."""
    facts = good_facts(in_response_to=None, subject_in_response_to=REQUEST_ID)

    assert check_in_response_to(facts, expectations()).passed


def test_rejects_a_login_we_have_already_accepted() -> None:
    result = check_not_replayed(good_facts(), already_seen=True)

    assert not result.passed
    assert "replay" in result.detail


def test_accepts_a_login_we_have_not_seen_before() -> None:
    assert check_not_replayed(good_facts(), already_seen=False).passed


def test_a_replayed_login_is_rejected_overall_even_though_everything_else_is_fine() -> None:
    """The whole point of remembering them. Nothing else about it looks wrong."""
    results = run_all_checks(good_facts(), expectations(), now=NOW, already_seen=True)

    assert not all_passed(results)
    assert failed_names(results) == ["not_replayed"]
