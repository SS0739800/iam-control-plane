"""Logging people in with SAML.

checks.py   the rules a login has to pass. Pure comparisons, no XML, no crypto,
            so it runs and is tested anywhere including Windows.
reader.py   pulls the facts out of the XML and verifies the signature. This is the
            only part that needs xmlsec, so it only runs in the container.

The split is on purpose: see docs/adr/0005-validate-assertions-ourselves.md.
"""

from __future__ import annotations

from iam.saml.checks import (
    DEFAULT_CLOCK_SKEW,
    SAML_SUCCESS,
    AssertionFacts,
    CheckResult,
    Expectations,
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
    "all_passed",
    "failed_names",
    "run_all_checks",
]
