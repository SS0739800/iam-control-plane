"""Logging people in with SAML.

sp.py            our side of it: who we are, and the request that starts a login.
reader.py        pulls the facts out of the XML and verifies the signature.
checks.py        the rules a login has to pass once it's been read.
provisioning.py  turning a passed login into a person in the directory.
sessions.py      keeping them signed in afterwards.

reader.py is the only one of these that needs xmlsec, so it's the only one that
can't run on Windows. Everything else is plain comparisons and database work and
runs anywhere. See docs/adr/0005-validate-assertions-ourselves.md for why it's
split this way.
"""

from __future__ import annotations

from iam.saml.checks import (
    DEFAULT_CLOCK_SKEW,
    SAML_SUCCESS,
    AssertionFacts,
    CheckResult,
    Expectations,
    MalformedResponse,
    all_passed,
    failed_names,
    run_all_checks,
)

__all__ = [
    "DEFAULT_CLOCK_SKEW",
    "SAML_SUCCESS",
    "AssertionFacts",
    "CheckResult",
    "Expectations",
    "MalformedResponse",
    "all_passed",
    "failed_names",
    "run_all_checks",
]
