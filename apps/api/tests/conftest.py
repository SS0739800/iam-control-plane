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
from iam.routers.saml import (
    _logout_request_reader,
    _logout_response_reader,
    _response_reader,
)
from tests.saml_harness import (
    ConsoleUsers,
    Scenario,
    StubLogoutReader,
    StubReader,
    clean_up,
    create_console_users,
    new_console_users,
    new_scenario,
    remove_console_users,
)
from tests.support import (
    TEST_DATABASE_ENV_VAR,
    UNREACHABLE_DATABASE_URL,
    ScimCaller,
    build_settings,
    create_scim_client,
    database_url,
    new_scim_caller,
    remove_scim_client,
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
def console() -> Iterator[ConsoleUsers]:
    """One console user per role, so a test can call an endpoint as any of them.

    Nothing is seeded into the test database, so a test that wants to act as an
    admin has to create one first.
    """
    made = new_console_users()
    create_console_users(made)
    yield made
    remove_console_users(made)


@pytest.fixture
def caller() -> Iterator[ScimCaller]:
    """A usable SCIM bearer token, and everything it created cleaned up after."""
    made = new_scim_caller()
    create_scim_client(made)
    yield made
    remove_scim_client(made)


@pytest.fixture
def saml_logout_reader() -> StubLogoutReader:
    """Stands in for reading a provider's logout request."""
    return StubLogoutReader()


@pytest.fixture
def saml_logout_response_reader() -> StubLogoutReader:
    """Stands in for reading a provider's logout confirmation."""
    return StubLogoutReader()


@pytest.fixture
def saml_client(
    saml_reader: StubReader,
    saml_logout_reader: StubLogoutReader,
    saml_logout_response_reader: StubLogoutReader,
) -> Iterator[TestClient]:
    """A client whose SAML endpoints read messages through the stubs.

    Overriding the private dependencies directly is deliberate: they are the seams
    the endpoints were given so everything downstream of the signature check can be
    tested without xmlsec.
    """
    app = create_app(build_settings(database_url()))
    app.dependency_overrides[_response_reader] = lambda: saml_reader
    app.dependency_overrides[_logout_request_reader] = lambda: saml_logout_reader
    app.dependency_overrides[_logout_response_reader] = lambda: saml_logout_response_reader
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
