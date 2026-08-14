"""Shared setup for the tests.

There are three client fixtures on purpose:

`client` points at a database that isn't there. Anything that should work without
Postgres uses this one, so you can run most of the suite with nothing else
started.

`db_client` points at a real Postgres from IAM_TEST_DATABASE_URL, and skips if
that isn't set. CI sets it from a container.

`saml_client` is a db_client whose SAML endpoints read logins through a stub
instead of xmlsec, which doesn't install on Windows. See tests/saml_harness.py
for what that stub does and does not replace.

The first two use TestClient as a `with` block, because that's what runs the
app's startup code. httpx's ASGITransport skips startup, and then
app.state.sessionmaker isn't there.

The settings helpers live in tests/support.py rather than here, so saml_harness
can use them without importing this module and creating a cycle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from iam.db import build_engine, build_sessionmaker
from iam.main import create_app
from iam.routers.saml import _response_reader
from tests.saml_harness import Scenario, StubReader, clean_up, new_scenario
from tests.support import (
    TEST_DATABASE_ENV_VAR,
    UNREACHABLE_DATABASE_URL,
    build_settings,
    database_url,
)

__all__ = [
    "TEST_DATABASE_ENV_VAR",
    "UNREACHABLE_DATABASE_URL",
    "build_settings",
]


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A client with no working database."""
    with TestClient(create_app(build_settings())) as test_client:
        yield test_client


@pytest.fixture
def db_client() -> Iterator[TestClient]:
    """A client with a real Postgres behind it. Skips if there isn't one."""
    with TestClient(create_app(build_settings(database_url()))) as test_client:
        yield test_client


@pytest.fixture
def scenario() -> Iterator[Scenario]:
    """Unique names for one SAML test, and the cleanup afterwards."""
    made = new_scenario()
    yield made
    clean_up(made)


@pytest.fixture
def saml_reader() -> StubReader:
    """Stands in for the one module that needs xmlsec. See tests/saml_harness.py."""
    return StubReader()


@pytest.fixture
def saml_client(saml_reader: StubReader) -> Iterator[TestClient]:
    """A client whose SAML endpoints read logins through the stub.

    Overriding the private dependency directly is deliberate: it is the seam the
    endpoint was given so everything downstream of the signature check can be
    tested without xmlsec.
    """
    app = create_app(build_settings(database_url()))
    app.dependency_overrides[_response_reader] = lambda: saml_reader
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A real database session that gets rolled back at the end.

    Rolled back rather than deleting what we made, because the audit log rejects
    DELETE, so a test that wrote entries has no other way to tidy up. Each test
    gets its own connection too, so one failed statement can't break the next test.
    """
    engine = build_engine(build_settings(database_url()))
    try:
        async with build_sessionmaker(engine)() as session:
            yield session
            await session.rollback()
    finally:
        await engine.dispose()
