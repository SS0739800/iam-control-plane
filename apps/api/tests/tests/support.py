"""Settings helpers the test suite builds apps from.

Its own module rather than living in conftest.py, because saml_harness.py needs
them and conftest.py needs saml_harness.py. Putting them here is what stops those
two importing each other.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, TypeVar

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.config import Settings
from iam.db import build_engine, build_sessionmaker
from iam.models.group import Group, GroupMember
from iam.models.saml import SamlSession
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.scim.constants import SCIM_MEDIA_TYPE
from iam.tokens import hash_token, new_token

if TYPE_CHECKING:
    from iam.saml.keys import Keypair

T = TypeVar("T")

# Port 1 on localhost. Nothing is listening there, and it fails straight away
# instead of hanging for a timeout like a made-up hostname would.
UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/absent"

TEST_DATABASE_ENV_VAR = "IAM_TEST_DATABASE_URL"


@lru_cache(maxsize=1)
def signing_keypair() -> Keypair:
    """A throwaway signing keypair, for tests that build a production app.

    Production refuses to start without one, which is the point — but a test about
    authentication should not have to care, so this exists to satisfy the guard
    without making every such test generate its own RSA key.

    Cached: keygen costs about a tenth of a second, and a test suite that builds
    several production apps would otherwise pay it each time.
    """
    from iam.saml.keys import generate

    return generate(common_name="http://localhost:8080")


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


@dataclass(frozen=True, slots=True)
class ScimCaller:
    """A SCIM client and the token it was issued, unique to one test.

    The token is generated here and only its hash is stored, the same way a real
    one would be — so these tests exercise the actual lookup path rather than a
    shortcut around it.
    """

    suffix: str
    token: str

    @property
    def name(self) -> str:
        return f"test-client-{self.suffix}"

    @property
    def user_name(self) -> str:
        return f"scim.{self.suffix}@demo.local"

    @property
    def other_user_name(self) -> str:
        """A second person, for the tests that need more than one row."""
        return f"scim.other.{self.suffix}@demo.local"

    @property
    def group_name(self) -> str:
        return f"SCIM Test Group {self.suffix}"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": SCIM_MEDIA_TYPE}


def new_scim_caller() -> ScimCaller:
    return ScimCaller(suffix=uuid.uuid4().hex[:12], token=new_token())


def create_scim_client(caller: ScimCaller) -> None:
    async def work(session: AsyncSession) -> None:
        session.add(ScimClient(name=caller.name, token_hash=hash_token(caller.token), enabled=True))

    run_db(work)


def remove_scim_client(caller: ScimCaller) -> None:
    """Take away everything one SCIM test made.

    Order matters: sessions and memberships reference people, and people are
    referenced by nothing else here, so they go last.
    """

    async def work(session: AsyncSession) -> None:
        names = (caller.user_name, caller.other_user_name)
        people = (await session.scalars(select(User).where(User.user_name.in_(names)))).all()
        for person in people:
            await session.execute(delete(SamlSession).where(SamlSession.user_id == person.id))
            await session.execute(delete(GroupMember).where(GroupMember.user_id == person.id))
        await session.execute(delete(Group).where(Group.name.like(f"%{caller.suffix}%")))
        await session.execute(delete(User).where(User.user_name.in_(names)))
        await session.execute(delete(ScimClient).where(ScimClient.name == caller.name))

    run_db(work)


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
