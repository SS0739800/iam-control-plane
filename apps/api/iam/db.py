"""Sets up the database connection and hands sessions to requests.

Getting the pooler mode wrong causes intermittent failures under load that are
hard to reproduce locally. See build_engine below.
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
    """Build the database engine for however we're reaching Postgres.

    In transaction-mode pooling (Supabase port 6543, Neon's `-pooler` host), asyncpg's
    prepared statement names can collide across connections since the pool hands out
    shared connections. That causes rare DuplicatePreparedStatementError failures under
    load that never show up locally. Turning off both statement caches fixes it. We
    also skip our own pool since the upstream pooler already pools connections.
    """
    kwargs: dict[str, Any] = {"echo": settings.db_echo}

    if settings.db_pooler_mode == "transaction":
        kwargs["poolclass"] = NullPool
        kwargs["connect_args"] = {
            "statement_cache_size": 0,  # asyncpg's own cache
            "prepared_statement_cache_size": 0,  # SQLAlchemy's asyncpg dialect
        }
    else:
        # Our own connection pool. Fine for local Postgres, a direct connection, or
        # session-mode pooling.
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 5
        kwargs["pool_pre_ping"] = True
        kwargs["pool_recycle"] = 1800

    return create_async_engine(settings.app_url, **kwargs)


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session bound to this request.

    The sessionmaker is stored on app.state so tests can swap it without touching
    module globals.
    """
    factory: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with factory() as session:
        yield session
