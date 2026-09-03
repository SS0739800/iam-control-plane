"""Cheap checks on the shape of the repository itself.

A complete copy of the test suite once ended up at tests/tests/, and a
complete copy of the source package at iam/iam/. Both were committed and
nothing failed, since every test still passed. They just doubled everything
quietly: the suite went from 590 tests to 1,269 and three minutes to ten and
a half hours, since the integration tests ran twice against one database and
spent most of that time contending with themselves.

The duplicated source package was more dangerous: iam.iam.models was
importable, and importing it would register every SQLAlchemy table a second
time against a second Base.

The first version of this file only checked tests/, so the source copy would
have survived it — these checks are written against the general pattern
instead of just the one case that happened.

These run in milliseconds and need nothing.
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).parent
APP_ROOT = TESTS_DIR.parent
PACKAGE_DIR = APP_ROOT / "iam"


def test_there_is_no_nested_tests_directory() -> None:
    """A copy of the suite inside the suite doubles every test silently.

    A regression test: tests/tests/ was committed once, and the only symptom
    was the suite taking ten hours instead of three minutes.
    """
    nested = TESTS_DIR / "tests"

    assert not nested.exists(), (
        f"{nested} exists, which means every test in it is collected twice. "
        "Delete it — it is almost certainly a stray copy."
    )


def test_the_package_does_not_contain_a_copy_of_itself() -> None:
    """iam/iam/ is worse than tests/tests/, since it's importable.

    Importing iam.iam.models would build every table a second time against a
    second declarative Base, which doesn't fail at import and goes wrong
    later in ways that look nothing like the cause.
    """
    nested = PACKAGE_DIR / "iam"

    assert not nested.exists(), (
        f"{nested} exists. It is a second copy of the package, it is importable as "
        "iam.iam, and importing it would register every table twice. Delete it."
    )


def test_nothing_anywhere_is_nested_inside_a_directory_of_its_own_name() -> None:
    """The general form of both mistakes, so a third one isn't a new surprise.

    Written against the tree rather than a list of known cases — the first
    version of this file checked only tests/ and the source copy walked
    straight past it.
    """
    # Caches mirror whatever tree they were built against, so a stale one
    # reports a duplicate that no longer exists. Excluded rather than
    # cleaned, since a test that deletes build artifacts to pass is worse.
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

    A duplicated file anywhere below tests/ has the same effect; a nested
    directory is just one way it can happen.
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
    """The harness modules are named so pytest ignores them, and that has to
    stay true — they hold fixtures and stubs, not tests. Named test_something
    they'd be collected, and their helper functions taking arguments pytest
    can't supply would turn into errors.
    """
    for helper in ("saml_harness.py", "idp_harness.py", "support.py"):
        assert (TESTS_DIR / helper).exists(), f"{helper} has moved or been renamed"
        assert not helper.startswith("test_"), f"{helper} would be collected as a test"
