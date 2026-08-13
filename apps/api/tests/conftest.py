"""Shared setup for the tests.

There are two client fixtures on purpose:

`client` points at a database that isn't there. Anything that should work without
Postgres uses this one, so you can run most of the suite with nothing else
started.

`db_client` points at a real Postgres from IAM_TEST_DATABASE_URL, and skips if
that isn't set. CI sets it from a container.

Both use TestClient as a `with` block, because that's what runs the app's startup
code. httpx's ASGITransport skips startup, and then app.state.sessionmaker isn't
there.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.db import build_engine, build_sessionmaker
from iam.main import create_app

# Port 1 on localhost. Nothing is listening there, and it fails straight away
# instead of hanging for a timeout like a made-up hostname would.
UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent"

TEST_DATABASE_ENV_VAR = "IAM_TEST_DATABASE_URL"


def build_settings(database_url: str = UNREACHABLE_DATABASE_URL) -> Settings:
    """Settings for a test app. Values passed here beat whatever's in the shell."""
    return Settings(
        app_env="ci",
        database_url=database_url,
        session_secret="test-secret-deliberately-not-the-placeholder",
        log_level="WARNING",
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A client with no working database."""
    with TestClient(create_app(build_settings())) as test_client:
        yield test_client


@pytest.fixture
def db_client() -> Iterator[TestClient]:
    """A client with a real Postgres behind it. Skips if there isn't one."""
    database_url = os.environ.get(TEST_DATABASE_ENV_VAR)
    if not database_url:
        pytest.skip(f"{TEST_DATABASE_ENV_VAR} is not set")

    with TestClient(create_app(build_settings(database_url))) as test_client:
        yield test_client


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A real database session that gets rolled back at the end.

    Rolled back rather than deleting what we made, because the audit log rejects
    DELETE, so a test that wrote entries has no other way to tidy up. Each test
    gets its own connection too, so one failed statement can't break the next test.
    """
    database_url = os.environ.get(TEST_DATABASE_ENV_VAR)
    if not database_url:
        pytest.skip(f"{TEST_DATABASE_ENV_VAR} is not set")

    engine = build_engine(build_settings(database_url))
    try:
        async with build_sessionmaker(engine)() as session:
            yield session
            await session.rollback()
    finally:
        await engine.dispose()
