"""The base class all tables inherit from, plus how constraints get named.

The naming rules matter more than they look. Without them, Alembic writes
migrations using whatever names Postgres invented, and then can't drop those
constraints when you roll back. Easy to set now, painful to change once
migrations exist.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for every model in the schema."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
