"""Database engine construction and the request-scoped session dependency.

The pooler-mode branching here is the whole reason this module exists. Getting
it wrong on Supabase produces an intermittent failure that only appears under
concurrency, which is a miserable thing to debug later.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

# Imported at runtime, not under TYPE_CHECKING: FastAPI resolves dependency
# annotations with get_type_hints() at startup, so every annotation on a
# dependency function must exist in the module namespace.
from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from iam.config import Settings


def build_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine, adapted to how we reach Postgres.

    ``transaction`` mode (Supavisor, port 6543) multiplexes many client
    connections onto fewer server connections. asyncpg names its prepared
    statements per-connection, so a reused name can land on a backend that has
    never seen it — surfacing as an intermittent DuplicatePreparedStatementError
    under load and never in local testing. Disabling both caches is the fix, and
    SQLAlchemy must not pool on top of a pooler.
    """
    kwargs: dict[str, Any] = {"echo": settings.db_echo}

    if settings.db_pooler_mode == "transaction":
        kwargs["poolclass"] = NullPool
        kwargs["connect_args"] = {
            "statement_cache_size": 0,  # asyncpg's own cache
            "prepared_statement_cache_size": 0,  # SQLAlchemy's asyncpg dialect
        }
    else:
        # A real connection pool we own: local Postgres, a direct connection,
        # or Supabase session mode.
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 5
        kwargs["pool_pre_ping"] = True
        kwargs["pool_recycle"] = 1800

    return create_async_engine(settings.database_url, **kwargs)


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session bound to this request.

    The sessionmaker is built once in the app lifespan and stored on app.state,
    so tests can swap it without touching module globals.
    """
    factory: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with factory() as session:
        yield session
