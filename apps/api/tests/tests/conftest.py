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
from iam.routers.idp import (
    _assertion_signer,
    _authn_request_reader,
    _document_signer,
)
from iam.routers.idp import _logout_request_reader as _idp_logout_request_reader
from iam.routers.saml import (
    _logout_request_reader,
    _logout_response_reader,
    _response_reader,
)
from tests.idp_harness import (
    AppScenario,
    StubAuthnReader,
    StubDocumentSigner,
    StubSigner,
    new_app_scenario,
)

# Both harnesses have a StubLogoutReader, because both sides of SAML receive logout
# requests. Aliased rather than renamed so each stays named after its own side.
from tests.idp_harness import StubLogoutReader as StubIdpLogoutReader
from tests.idp_harness import clean_up as clean_up_app
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
def app_scenario() -> Iterator[AppScenario]:
    """Unique names for one identity-provider test, and the cleanup afterwards."""
    made = new_app_scenario()
    yield made
    clean_up_app(made)


@pytest.fixture
def authn_reader() -> StubAuthnReader:
    """Stands in for reading an application's login request. See tests/idp_harness.py."""
    return StubAuthnReader()


@pytest.fixture
def assertion_signer() -> StubSigner:
    """Stands in for xmlsec signing the response we send back."""
    return StubSigner()


@pytest.fixture
def idp_logout_reader() -> StubIdpLogoutReader:
    """Stands in for reading an application's logout request."""
    return StubIdpLogoutReader()


@pytest.fixture
def document_signer() -> StubDocumentSigner:
    """Stands in for signing a document with no assertion in it."""
    return StubDocumentSigner()


@pytest.fixture
def idp_client(
    authn_reader: StubAuthnReader,
    assertion_signer: StubSigner,
    idp_logout_reader: StubIdpLogoutReader,
    document_signer: StubDocumentSigner,
) -> Iterator[TestClient]:
    """A client whose /idp endpoints read and sign through the stubs.

    The same two seams as saml_client, in the other direction: everything the
    endpoint decides is the real code, and only the two steps that need xmlsec are
    replaced.
    """
    app = create_app(build_settings(database_url()))
    app.dependency_overrides[_authn_request_reader] = lambda: authn_reader
    app.dependency_overrides[_assertion_signer] = lambda: assertion_signer
    app.dependency_overrides[_idp_logout_request_reader] = lambda: idp_logout_reader
    app.dependency_overrides[_document_signer] = lambda: document_signer
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
