"""Settings helpers the test suite builds apps from.

Its own module rather than living in conftest.py, because saml_harness.py needs
them and conftest.py needs saml_harness.py. Putting them here is what stops those
two importing each other.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from typing import TypeVar

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.db import build_engine, build_sessionmaker

T = TypeVar("T")

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


def database_url() -> str:
    """The real Postgres to test against, or skip the test."""
    url = os.environ.get(TEST_DATABASE_ENV_VAR)
    if not url:
        pytest.skip(f"{TEST_DATABASE_ENV_VAR} is not set")
    return url


def run_db(work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    """Run one piece of database work on its own engine, and commit it.

    For setting up and checking on a test that drives the app over HTTP. Its own
    engine, because the app under test has one of its own running in the
    TestClient's event loop, and sharing a connection across the two would be the
    interesting kind of flaky.
    """

    async def main() -> T:
        engine = build_engine(build_settings(database_url()))
        try:
            async with build_sessionmaker(engine)() as session:
                result = await work(session)
                await session.commit()
                return result
        finally:
            await engine.dispose()

    return asyncio.run(main())
