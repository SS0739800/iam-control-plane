"""Sets up the database connection and hands sessions to requests.

The pooler-mode branch below is the reason this file needs a comment at all. Get it
wrong on Supabase and things break only sometimes, only under load, which is
horrible to track down later.
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
    """Build the database connection, set up for however we're reaching Postgres.

    Supabase's transaction mode (port 6543) shares a small number of real database
    connections between many clients. asyncpg gives its prepared statements names
    that only make sense on one connection, so a reused name can land on a
    connection that's never seen it. You get an occasional
    DuplicatePreparedStatementError under load and never once while testing
    locally. Turning both caches off fixes it, and we mustn't pool on top of
    something that's already pooling.
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
        # Supabase session mode.
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
