"""Declarative base and constraint naming convention.

The naming convention is not cosmetic: without it, Alembic autogenerate emits
migrations with server-assigned constraint names that it then cannot drop on the
way back down. Setting it before the first migration exists is the cheap moment;
changing it afterwards means rewriting history.
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
