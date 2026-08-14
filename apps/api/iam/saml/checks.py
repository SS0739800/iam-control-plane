"""The checks a login has to pass before we believe it.

Nothing in this file imports xmlsec or touches XML. It works on facts already
pulled out of the document, which has two benefits: these run and are tested on
any machine including Windows, and each check is a small function you can read on
its own.

The order below is roughly cheapest-first, but every check runs regardless of
whether an earlier one failed. That's on purpose. "Signature is fine, audience is
wrong" is a configuration mistake and "signature is wrong and so is everything
else" is something else entirely, and you can only tell them apart if you have all
the answers.

See docs/adr/0005-validate-assertions-ourselves.md for why these are ours rather
than a library's.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

SAML_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


class MalformedResponse(Exception):
    """The response could not be read at all.

    Different from a login that reads fine but fails a check. This one means there
    was nothing to check, so it's a 400 rather than a rejected login.

    Raised by reader.py, but defined here so the endpoint can catch it without
    importing the one module that needs xmlsec. See ADR 0004.
    """


DEFAULT_CLOCK_SKEW = dt.timedelta(minutes=3)
"""How far out a provider's clock is allowed to be.

Some slack is necessary; machines disagree about the time and a login that took
400ms shouldn't fail because of it. Too much slack and an expired login stays
usable, so this stays small. Three minutes is the usual choice.
"""


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One check, and how it went."""

    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        """Shape stored on the audit entry and shown in the inspector."""
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class AssertionFacts:
    """What we read out of the login document, before judging any of it.

    Separating reading from judging is what keeps this file free of XML. The reader
    fills this in; everything below only looks at it.
    """

    assertion_id: str
    issuer: str
    status_code: str

    audiences: tuple[str, ...] = ()
    destination: str | None = None
    in_response_to: str | None = None

    not_before: dt.datetime | None = None
    not_on_or_after: dt.datetime | None = None

    subject_not_on_or_after: dt.datetime | None = None
    subject_recipient: str | None = None
    subject_in_response_to: str | None = None

    name_id: str | None = None
    name_id_format: str | None = None
    session_index: str | None = None

    attributes: dict[str, list[str]] = field(default_factory=dict)

    # Filled in by the reader, which is the only part that does cryptography.
    signature_verified: bool = False
    assertion_was_signed: bool = False


@dataclass(frozen=True, slots=True)
class Expectations:
    """What we're comparing the login against."""

    our_entity_id: str
    our_acs_url: str
    idp_entity_id: str
    expected_request_id: str | None
    require_signed_assertion: bool = True
    clock_skew: dt.timedelta = DEFAULT_CLOCK_SKEW


def check_status(facts: AssertionFacts) -> CheckResult:
    """Did the provider actually say the login worked.

    A response can be perfectly signed and still mean "no". Reading the subject out
    of a failed response and letting them in is a real mistake people make.
    """
    ok = facts.status_code == SAML_SUCCESS
    return CheckResult(
        name="status",
        passed=ok,
        detail=(
            "provider reported success"
            if ok
            else f"provider reported {facts.status_code or 'no status'}"
        ),
    )


def check_signature(facts: AssertionFacts) -> CheckResult:
    """Was the signature real, and made with the key we expect.

    The answer comes from the reader, which uses xmlsec. This only reports it, so
    it shows up in the checklist next to everything else.
    """
    return CheckResult(
        name="signature",
        passed=facts.signature_verified,
        detail=(
            "signed with the provider's key"
            if facts.signature_verified
            else "signature missing or does not match the provider's certificate"
        ),
    )


def check_assertion_signed(facts: AssertionFacts, expected: Expectations) -> CheckResult:
    """Was the assertion itself signed, not just the envelope around it.

    This matters more than it sounds. If only the outer response is signed, the
    signature covers the wrapper and someone can potentially swap what's inside it
    while the signature still checks out. Insisting the assertion carries its own
    signature closes that off.
    """
    if not expected.require_signed_assertion:
        return CheckResult(
            name="assertion_signed",
            passed=True,
            detail="not required for this provider",
        )

    ok = facts.assertion_was_signed
    return CheckResult(
        name="assertion_signed",
        passed=ok,
        detail=(
            "the assertion carries its own signature"
            if ok
            else "only the outer response was signed, which leaves the contents swappable"
        ),
    )


def check_issuer(facts: AssertionFacts, expected: Expectations) -> CheckResult:
    """Did it come from the provider we think it did."""
    ok = facts.issuer == expected.idp_entity_id
    return CheckResult(
        name="issuer",
        passed=ok,
        detail=(
            f"from {facts.issuer}"
            if ok
            else f"from {facts.issuer or 'nobody'}, expected {expected.idp_entity_id}"
        ),
    )


def check_audience(facts: AssertionFacts, expected: Expectations) -> CheckResult:
    """Was this meant for us.

    Skip this one and a login the provider issued for a different application gets
    you into this one. Anybody with an account on that other app becomes a user
    here.
    """
    ok = expected.our_entity_id in facts.audiences
    listed = ", ".join(facts.audiences) if facts.audiences else "nobody"
    return CheckResult(
        name="audience",
        passed=ok,
        detail=(
            f"addressed to us ({expected.our_entity_id})"
            if ok
            else f"addressed to {listed}, not to {expected.our_entity_id}"
        ),
    )


def check_destination(facts: AssertionFacts, expected: Expectations) -> CheckResult:
    """Was it sent to our address.

    Stops a login captured on the way to somewhere else being pointed at us.
    Providers may leave this out, and the spec allows that, so an absent value is
    not treated as a failure.
    """
    if facts.destination is None:
        return CheckResult(
            name="destination",
            passed=True,
            detail="provider did not state a destination, which is allowed",
        )

    ok = facts.destination.rstrip("/") == expected.our_acs_url.rstrip("/")
    return CheckResult(
        name="destination",
        passed=ok,
        detail=(
            "sent to our login address"
            if ok
            else f"sent to {facts.destination}, ours is {expected.our_acs_url}"
        ),
    )


def check_timing(facts: AssertionFacts, expected: Expectations, now: dt.datetime) -> CheckResult:
    """Is it currently valid: not expired, and not dated in the future.

    Both ends matter. No upper bound and an old login works forever. No lower bound
    and a provider with a fast clock hands out logins that are valid before they
    were issued.
    """
    skew = expected.clock_skew

    if facts.not_before is not None and now + skew < facts.not_before:
        return CheckResult(
            name="timing",
            passed=False,
            detail=f"not valid until {facts.not_before.isoformat()}, it is now {now.isoformat()}",
        )

    if facts.not_on_or_after is not None and now - skew >= facts.not_on_or_after:
        return CheckResult(
            name="timing",
            passed=False,
            detail=f"expired at {facts.not_on_or_after.isoformat()}, it is now {now.isoformat()}",
        )

    return CheckResult(
        name="timing",
        passed=True,
        detail=f"within its validity window, allowing {int(skew.total_seconds())}s of clock drift",
    )


def check_subject_confirmation(
    facts: AssertionFacts, expected: Expectations, now: dt.datetime
) -> CheckResult:
    """Is the part that says "this person, here, now" still good.

    An assertion has an outer validity window and a tighter one on the subject.
    The tighter one is the one that says this login is for us specifically, and it
    is usually only valid for a few minutes.
    """
    skew = expected.clock_skew

    if facts.subject_not_on_or_after is not None and now - skew >= facts.subject_not_on_or_after:
        return CheckResult(
            name="subject_confirmation",
            passed=False,
            detail=f"the subject window closed at {facts.subject_not_on_or_after.isoformat()}",
        )

    if facts.subject_recipient is not None and facts.subject_recipient.rstrip(
        "/"
    ) != expected.our_acs_url.rstrip("/"):
        return CheckResult(
            name="subject_confirmation",
            passed=False,
            detail=f"names {facts.subject_recipient} as the recipient, not us",
        )

    return CheckResult(
        name="subject_confirmation",
        passed=True,
        detail="names us as the recipient and is still in date",
    )


def check_in_response_to(facts: AssertionFacts, expected: Expectations) -> CheckResult:
    """Is this answering a login we actually asked for.

    Without this, anyone can post a valid-looking login at us out of nowhere and be
    let in. That's the whole shape of the attack, and matching the id we sent is
    what prevents it.

    A login with no id at all is one the provider started by itself. We only allow
    that when we weren't waiting for anything.
    """
    quoted = facts.in_response_to or facts.subject_in_response_to

    if expected.expected_request_id is None:
        if quoted is None:
            return CheckResult(
                name="in_response_to",
                passed=True,
                detail="provider-initiated login, and we were not expecting a reply",
            )
        return CheckResult(
            name="in_response_to",
            passed=False,
            detail=f"quotes request {quoted}, but we have no record of sending it",
        )

    if quoted is None:
        return CheckResult(
            name="in_response_to",
            passed=False,
            detail=f"quotes no request, but we were waiting on {expected.expected_request_id}",
        )

    ok = quoted == expected.expected_request_id
    return CheckResult(
        name="in_response_to",
        passed=ok,
        detail=(
            "answers the request we sent"
            if ok
            else f"answers {quoted}, but we sent {expected.expected_request_id}"
        ),
    )


def check_not_replayed(facts: AssertionFacts, already_seen: bool) -> CheckResult:
    """Have we accepted this exact login before.

    Every login carries a unique id. Seeing one twice means somebody kept a copy
    and sent it again. Without this check, one captured login works over and over
    until it expires.
    """
    return CheckResult(
        name="not_replayed",
        passed=not already_seen,
        detail=(
            f"first time we have seen {facts.assertion_id}"
            if not already_seen
            else f"{facts.assertion_id} has been used before, so this is a replay"
        ),
    )


def run_all_checks(
    facts: AssertionFacts,
    expected: Expectations,
    *,
    now: dt.datetime,
    already_seen: bool,
) -> list[CheckResult]:
    """Run every check and return all the answers, in display order.

    Deliberately does not stop at the first failure. The inspector shows the whole
    list, and a login that fails three checks tells you something different from one
    that fails a single one.
    """
    return [
        check_status(facts),
        check_signature(facts),
        check_assertion_signed(facts, expected),
        check_issuer(facts, expected),
        check_audience(facts, expected),
        check_destination(facts, expected),
        check_timing(facts, expected, now),
        check_subject_confirmation(facts, expected, now),
        check_in_response_to(facts, expected),
        check_not_replayed(facts, already_seen),
    ]


def all_passed(results: list[CheckResult]) -> bool:
    """Whether the login is acceptable. Every check has to pass, no exceptions."""
    return all(result.passed for result in results)


def failed_names(results: list[CheckResult]) -> list[str]:
    """Names of the checks that failed, for the log line and the error message."""
    return [result.name for result in results if not result.passed]
