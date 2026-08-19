"""Tests for cursors and page-size limits.

Plain functions, no database needed. The cursor is the bit worth testing properly:
it goes out over the API, so anything that saved one has to keep working after we
deploy again.
"""

from __future__ import annotations

import pytest

from iam.api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    clamp_limit,
    decode_cursor,
    encode_cursor,
)


@pytest.mark.parametrize("row_id", [1, 42, 45_829, 2**53])
def test_cursor_round_trips(row_id: int) -> None:
    assert decode_cursor(encode_cursor(row_id)) == row_id


def test_cursor_is_opaque() -> None:
    """You shouldn't be able to read the row id straight out of it.

    Not for security. It's so nobody writes code that picks the cursor apart, which
    would break the day we put something else in there.
    """
    assert "45829" not in encode_cursor(45_829)


def test_cursor_has_no_padding() -> None:
    """The '=' that base64 adds survives most URLs but not all of them."""
    assert "=" not in encode_cursor(1)


@pytest.mark.parametrize("bad", ["", "!!!!", "not-base64", "___"])
def test_malformed_cursor_raises_value_error(bad: str) -> None:
    """The route turns this into a 400, since the caller sent it."""
    with pytest.raises(ValueError, match="cursor"):
        decode_cursor(bad)


def test_cursor_rejects_non_numeric_payload() -> None:
    """Real base64 that isn't a row id is still a bad cursor."""
    import base64

    forged = base64.urlsafe_b64encode(b"DROP TABLE users").decode().rstrip("=")
    with pytest.raises(ValueError, match="row id"):
        decode_cursor(forged)


def test_limit_defaults_when_absent() -> None:
    assert clamp_limit(None) == DEFAULT_LIMIT


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (1, 1),
        (50, 50),
        (MAX_LIMIT, MAX_LIMIT),
        (MAX_LIMIT + 1, MAX_LIMIT),
        (10**9, MAX_LIMIT),
        (0, 1),
        (-5, 1),
    ],
)
def test_limit_is_clamped(requested: int, expected: int) -> None:
    """Without an upper limit, one request could ask for the whole table."""
    assert clamp_limit(requested) == expected
