"""Making a provider's connection URL usable by asyncpg.

Every managed Postgres hands out a URL ending ``?sslmode=require``, since
that's what libpq and psycopg want. asyncpg takes ``ssl`` instead, has no
``**kwargs`` to absorb the difference, and SQLAlchemy passes query parameters
straight through untranslated.

So pasting a URL from a dashboard raises ``TypeError: connect() got an
unexpected keyword argument 'sslmode'`` on the first query. The readiness
endpoint hides exception messages since they can contain the connection
string, so production reports only ``{"detail": "TypeError"}``.

These tests cover this because it's the single most likely deploy mistake,
and the fix is a string rewrite that's easy to get subtly wrong — catching
the first query parameter but not a later one, or mangling an already-fine URL.
"""

from __future__ import annotations

import inspect
from typing import Any

import asyncpg
import pytest
from sqlalchemy.dialects.postgresql import asyncpg as pg_asyncpg
from sqlalchemy.engine.url import make_url

from iam.config import Settings, for_asyncpg

NEON = "postgresql+asyncpg://user:pw@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/iam"


def connect_kwargs(url: str) -> dict[str, Any]:
    """What SQLAlchemy's asyncpg dialect would actually hand to asyncpg.connect().

    Goes through the dialect rather than parsing the string ourselves, since
    the bug is that SQLAlchemy passes query parameters through untranslated —
    only the dialect's own output is convincing evidence either way.
    """
    _, kwargs = pg_asyncpg.dialect().create_connect_args(make_url(url))  # type: ignore[no-untyped-call]
    return dict(kwargs)


# ------------------------------------------------------------- the rewrite


def test_sslmode_becomes_ssl() -> None:
    assert for_asyncpg(f"{NEON}?sslmode=require") == f"{NEON}?ssl=require"


def test_it_works_when_sslmode_is_not_the_first_parameter() -> None:
    """The obvious implementation only handles "?sslmode=" and misses this one."""
    given = f"{NEON}?application_name=iam&sslmode=require"

    assert for_asyncpg(given) == f"{NEON}?application_name=iam&ssl=require"


def test_other_parameters_are_left_alone() -> None:
    given = f"{NEON}?sslmode=verify-full&application_name=iam&connect_timeout=10"
    rewritten = for_asyncpg(given)

    assert "ssl=verify-full" in rewritten
    assert "application_name=iam" in rewritten
    assert "connect_timeout=10" in rewritten
    assert "sslmode" not in rewritten


@pytest.mark.parametrize(
    "mode",
    ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"],
)
def test_every_libpq_mode_keeps_its_value(mode: str) -> None:
    """Only the key differs between the two libraries. asyncpg accepts the same set
    of values, so a rewrite that translated them would be inventing a problem."""
    assert for_asyncpg(f"{NEON}?sslmode={mode}") == f"{NEON}?ssl={mode}"


def test_a_url_with_no_ssl_parameter_is_untouched() -> None:
    """What local development uses. A plain URL must come out exactly as it went in."""
    plain = "postgresql+asyncpg://iam:iam@localhost:5432/iam"

    assert for_asyncpg(plain) == plain


def test_a_url_already_using_ssl_is_untouched() -> None:
    """Somebody who fixed it by hand should not have it fixed twice."""
    already = f"{NEON}?ssl=require"

    assert for_asyncpg(already) == already


def test_the_word_sslmode_elsewhere_in_the_url_is_not_rewritten() -> None:
    """Only a parameter key is a parameter key. A password containing the word, or a
    database named after it, must survive — the rewrite is anchored to ? and &."""
    odd = "postgresql+asyncpg://user:sslmode=hunter2@host/iam"

    assert for_asyncpg(odd) == odd


# --------------------------------------------- and asyncpg really accepts it


def test_the_rewritten_url_reaches_asyncpg_with_ssl() -> None:
    """The test that would have caught this before it shipped.

    Goes through SQLAlchemy's own dialect rather than trusting the string,
    since the only convincing check is what the dialect actually produces.
    """
    assert connect_kwargs(for_asyncpg(f"{NEON}?sslmode=require"))["ssl"] == "require"
    assert "sslmode" not in connect_kwargs(for_asyncpg(f"{NEON}?sslmode=require"))


def test_the_unrewritten_url_is_the_thing_that_breaks() -> None:
    """Proof the problem is real and not a precaution against nothing.

    asyncpg's connect() takes no **kwargs, so sslmode arriving here is a
    TypeError at connection time. If a future SQLAlchemy starts translating
    it, this test fails and the rewrite can go.
    """
    untouched = connect_kwargs(f"{NEON}?sslmode=require")
    assert "sslmode" in untouched, "SQLAlchemy now translates this; the rewrite is obsolete"

    accepted = inspect.signature(asyncpg.connect).parameters
    assert "sslmode" not in accepted
    assert "ssl" in accepted
    # No **kwargs to absorb it either, which is why this is a TypeError rather than
    # a silently ignored argument.
    assert not any(p.kind is p.VAR_KEYWORD for p in accepted.values())


# ------------------------------------------------------- through the settings


def test_the_app_url_is_rewritten() -> None:
    # _env_file=None throughout this section: Settings reads .env by default,
    # and a developer's ALEMBIC_DATABASE_URL would otherwise decide the
    # outcome of the fallback test below.
    settings = Settings(_env_file=None, database_url=f"{NEON}?sslmode=require")

    assert settings.app_url == f"{NEON}?ssl=require"


def test_the_migration_url_is_rewritten_too() -> None:
    """Alembic connects separately, and would fail the same way. It is also the first
    thing run against a new deployment, so this is where the mistake surfaces."""
    settings = Settings(
        _env_file=None,
        database_url=f"{NEON}?sslmode=require",
        alembic_database_url=f"{NEON.replace('-pooler', '')}?sslmode=require",
    )

    assert "ssl=require" in settings.migration_url
    assert "sslmode" not in settings.migration_url
    # And it is the direct host, not the pooled one — migrations cannot go through
    # transaction-mode pooling.
    assert "-pooler" not in settings.migration_url


def test_the_migration_url_falls_back_to_the_app_url_and_is_still_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What local development does: one server, one URL.

    The environment has to be cleared as well as the .env file. CI sets
    ALEMBIC_DATABASE_URL as a job-level variable, a second source _env_file
    says nothing about, so deleting it is the only way to test the fallback
    honestly.
    """
    monkeypatch.delenv("ALEMBIC_DATABASE_URL", raising=False)
    settings = Settings(_env_file=None, database_url=f"{NEON}?sslmode=require")

    assert settings.migration_url == f"{NEON}?ssl=require"


# ------------------------------------------------- channel_binding, which is worse


def test_channel_binding_is_dropped() -> None:
    """Neon's current connection strings include it, and asyncpg has no equivalent.

    Left in place it fails identically to sslmode (same TypeError), so fixing
    only sslmode would just move the problem.
    """
    given = f"{NEON}?sslmode=require&channel_binding=require"

    assert for_asyncpg(given) == f"{NEON}?ssl=require"


def test_channel_binding_on_its_own_leaves_a_clean_url() -> None:
    """No trailing "?" left behind when it was the only parameter."""
    assert for_asyncpg(f"{NEON}?channel_binding=require") == NEON


def test_channel_binding_really_would_have_broken_it() -> None:
    """Same shape as the sslmode proof: evidence the drop is necessary, and a
    tripwire for if asyncpg ever gains support and the drop should go."""
    forwarded = connect_kwargs(f"{NEON}?channel_binding=require")
    assert "channel_binding" in forwarded, "SQLAlchemy no longer forwards this"

    assert "channel_binding" not in inspect.signature(asyncpg.connect).parameters


def test_a_parameter_we_do_not_know_about_is_left_alone() -> None:
    """Not a whitelist.

    Silently discarding an unrecognized parameter would throw away somebody's
    intent without telling them. Better to leave it and let it fail somewhere
    with a name attached.
    """
    given = f"{NEON}?sslmode=require&target_session_attrs=read-write"

    assert for_asyncpg(given) == f"{NEON}?ssl=require&target_session_attrs=read-write"


def test_the_whole_thing_together_is_what_neon_actually_gives_you() -> None:
    """The exact shape pasted from the dashboard, end to end through the dialect."""
    pasted = f"{NEON}?sslmode=require&channel_binding=require"
    forwarded = connect_kwargs(for_asyncpg(pasted))

    assert forwarded["ssl"] == "require"
    assert "sslmode" not in forwarded
    assert "channel_binding" not in forwarded
    # And every argument left is one asyncpg will accept.
    accepted = inspect.signature(asyncpg.connect).parameters
    assert not set(forwarded) - set(accepted)
