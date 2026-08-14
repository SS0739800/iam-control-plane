"""Settings helpers the test suite builds apps from.

Its own module rather than living in conftest.py, because saml_harness.py needs
them and conftest.py needs saml_harness.py. Putting them here is what stops those
two importing each other.
"""

from __future__ import annotations

import os

import pytest

from iam.config import Settings

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
