"""Test fixtures.

Two client fixtures, deliberately:

``client``     points at an unreachable database. Everything that must work
               without Postgres uses this, so the suite runs on a laptop with
               nothing else started.
``db_client``  points at a real Postgres from IAM_TEST_DATABASE_URL and skips
               when it is absent. CI sets it from a service container.

Both use TestClient as a context manager, which runs the lifespan — httpx's
ASGITransport does not, and app.state.sessionmaker would be missing.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from iam.config import Settings
from iam.main import create_app

# Port 1 on loopback: nothing listens there, and it fails fast rather than
# hanging on a DNS or connect timeout the way a bogus hostname would.
UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent"

TEST_DATABASE_ENV_VAR = "IAM_TEST_DATABASE_URL"


def build_settings(database_url: str = UNREACHABLE_DATABASE_URL) -> Settings:
    """Settings for a test app. Explicit kwargs outrank the ambient environment."""
    return Settings(
        app_env="ci",
        database_url=database_url,
        session_secret="test-secret-deliberately-not-the-placeholder",
        log_level="WARNING",
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Client whose database is unreachable."""
    with TestClient(create_app(build_settings())) as test_client:
        yield test_client


@pytest.fixture
def db_client() -> Iterator[TestClient]:
    """Client backed by a real Postgres. Skips when one is not configured."""
    database_url = os.environ.get(TEST_DATABASE_ENV_VAR)
    if not database_url:
        pytest.skip(f"{TEST_DATABASE_ENV_VAR} is not set")

    with TestClient(create_app(build_settings(database_url))) as test_client:
        yield test_client
