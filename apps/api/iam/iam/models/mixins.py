"""Column sets that most tables reuse.

The database fills in the timestamps, not Python. That way rows created by a
migration, the seed script, or someone poking around in psql all get sensible
values instead of nothing.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column


class UUIDPrimaryKey:
    """A random id for the row.

    UUIDs instead of 1, 2, 3 because these ids end up in SAML and SCIM URLs. If
    they counted up, anyone could tell how many users we have and guess the next
    one.
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
