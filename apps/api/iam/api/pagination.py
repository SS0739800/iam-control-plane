"""Two ways of splitting results into pages, because the audit log needs its own.

Users, groups and apps use page numbers. People jump around in those lists
("page 7, sorted by department"), so they want a total count and the ability to
skip ahead. Those tables are small enough that it costs nothing.

The audit log uses a cursor instead. Two reasons. Asking Postgres for
`OFFSET 45000` makes it read and throw away 45,000 rows before giving you
anything, so the further you scroll the slower it gets. And because new entries
keep arriving at the top, every page number shifts down by one whenever someone
logs in, so scrolling skips entries or shows them twice. A cursor points at a
specific row instead, so neither happens.
"""

from __future__ import annotations

import base64
import binascii
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

DEFAULT_LIMIT = 25
MAX_LIMIT = 200
"""Upper limit. Without it, `?limit=1000000` is an easy way to knock us over."""


class Page(BaseModel, Generic[T]):
    """One page of results, with a total so the UI can show "page 3 of 12"."""

    items: list[T]
    total: int = Field(description="How many rows match the filters, ignoring paging.")
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class CursorPage(BaseModel, Generic[T]):
    """One page of the audit log.

    No total here. Counting the whole log on every request is wasted work, and the
    number would be out of date by the time you read it anyway.
    """

    items: list[T]
    limit: int
    next_cursor: str | None = Field(
        default=None,
        description="Pass as `cursor` to fetch the following page. Null at the end.",
    )


def encode_cursor(row_id: int) -> str:
    """Wrap a row id into a cursor string.

    Encoded so callers treat it as an opaque token instead of reading the row id
    out of it, which leaves room to change what's inside a cursor later without
    breaking anyone. Padding is stripped since `=` is awkward in a URL.
    """
    raw = base64.urlsafe_b64encode(str(row_id).encode())
    return raw.decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """Get the row id back out of a cursor.

    Raises:
        ValueError: The cursor is nonsense. Routes turn this into a 400, since a
            bad cursor means the caller sent something wrong, not that we broke.
    """
    padding = "=" * (-len(cursor) % 4)
    try:
        decoded = base64.urlsafe_b64decode(cursor + padding).decode()
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("cursor is not valid base64url") from exc

    if not decoded.isdigit():
        raise ValueError("cursor does not contain a row id")

    return int(decoded)


def clamp_limit(limit: int | None) -> int:
    """Coerce a requested page size into the allowed range."""
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(limit, MAX_LIMIT))
