"""Cheap checks on the shape of the repository itself.

This file exists because of one mistake, made twice in the same commit, that was
expensive out of all proportion to how obvious it was.

A complete copy of the test suite ended up at tests/tests/, and a complete copy of
the source package at iam/iam/. Both were committed. Nothing failed — every test
still passed — so nothing pointed at either.

What they did instead was double everything quietly. The suite went from 590 tests
to 1,269 and from three minutes to ten and a half hours, because the integration
tests ran twice against one database and spent most of that time contending with
themselves. mypy checked 170 files instead of 85. The only visible symptom was
slowness, which is the kind of symptom people learn to shrug at.

The duplicated source package was the more dangerous of the two: iam.iam.models was
importable, and importing it would have registered every SQLAlchemy table a second
time against a second Base.

The first version of this file only checked tests/, which is why the source copy
survived it. That is the lesson worth keeping — a guard aimed at the instance rather
than the mistake.

These run in milliseconds and need nothing.
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).parent
APP_ROOT = TESTS_DIR.parent
PACKAGE_DIR = APP_ROOT / "iam"


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


def test_the_package_does_not_contain_a_copy_of_itself() -> None:
    """iam/iam/ is worse than tests/tests/, because it is importable.

    Importing iam.iam.models would build every table a second time against a second
    declarative Base, which does not fail at import and goes wrong later in ways that
    look nothing like the cause.
    """
    nested = PACKAGE_DIR / "iam"

    assert not nested.exists(), (
        f"{nested} exists. It is a second copy of the package, it is importable as "
        "iam.iam, and importing it would register every table twice. Delete it."
    )


def test_nothing_anywhere_is_nested_inside_a_directory_of_its_own_name() -> None:
    """The general form of both mistakes, so a third one cannot be a new surprise.

    Written against the tree rather than a list of known cases, because the first
    version of this file checked only tests/ and the source copy walked straight
    past it.
    """
    # Caches mirror whatever tree they were built against, so a stale one reports a
    # duplicate that no longer exists. They are excluded rather than cleaned, because
    # a test that deletes build artefacts to make itself pass is a worse idea.
    ignored = {"__pycache__", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache"}

    offenders = []
    for path in APP_ROOT.rglob("*"):
        if not path.is_dir() or ignored & set(path.parts):
            continue
        if path.name == path.parent.name:
            offenders.append(str(path.relative_to(APP_ROOT)))

    assert not offenders, f"directories nested inside a directory of the same name: {offenders}"


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
