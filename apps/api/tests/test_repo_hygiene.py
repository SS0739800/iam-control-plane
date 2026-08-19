"""Cheap checks on the shape of the repository itself.

This file exists because of one mistake that was expensive out of all proportion to
how obvious it was. A complete copy of the test suite ended up at tests/tests/ and
was committed. Nothing failed — every test still passed — so nothing pointed at it.

What it did instead was double collection. The suite went from 590 tests to 1,269
and from three minutes to ten and a half hours, because the integration tests ran
twice against one database and spent most of that time contending with themselves.
The only visible symptom was a slow CI run, which is the kind of symptom people
learn to shrug at.

These run in milliseconds and need nothing.
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).parent


def test_there_is_no_nested_tests_directory() -> None:
    """A copy of the suite inside the suite doubles every test silently.

    Directly a regression test: tests/tests/ was committed once, and the only
    symptom was the suite taking ten hours instead of three minutes.
    """
    nested = TESTS_DIR / "tests"

    assert not nested.exists(), (
        f"{nested} exists, which means every test in it is collected twice. "
        "Delete it — it is almost certainly a stray copy."
    )


def test_no_test_file_appears_twice_under_a_different_path() -> None:
    """The general version of the check above.

    A duplicated file anywhere below tests/ has the same effect, and a nested
    directory is only the way it happened to happen.
    """
    by_name: dict[str, list[Path]] = {}
    for path in TESTS_DIR.rglob("test_*.py"):
        if "__pycache__" in path.parts:
            continue
        by_name.setdefault(path.name, []).append(path)

    duplicated = {
        name: [str(path.relative_to(TESTS_DIR)) for path in paths]
        for name, paths in by_name.items()
        if len(paths) > 1
    }

    assert not duplicated, f"the same test file exists at more than one path: {duplicated}"


def test_the_harnesses_are_not_collected_as_tests() -> None:
    """The harness modules are named so pytest ignores them, and that has to stay true.

    They hold fixtures and stubs, not tests. Named test_something they would be
    collected, and their helper functions taking arguments pytest cannot supply
    would turn into errors rather than anything useful.
    """
    for helper in ("saml_harness.py", "idp_harness.py", "support.py"):
        assert (TESTS_DIR / helper).exists(), f"{helper} has moved or been renamed"
        assert not helper.startswith("test_"), f"{helper} would be collected as a test"
