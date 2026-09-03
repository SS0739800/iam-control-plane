"""Column sets that most tables reuse.

Timestamps are filled in by the database, not Python, so rows created from
a migration, the seed script, or psql still get sensible values.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column


class UUIDPrimaryKey:
    """A random id for the row.

    UUIDs instead of sequential ints because these ids end up in SAML and
    SCIM URLs, and sequential ids would leak the row count and let someone
    guess the next one.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )


class Timestamps:
    """When the row was made and last changed. Both set by the database."""

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
