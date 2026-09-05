"""Sorting the user list.

The list is paged, so the order matters for more than looks: if two people sort
equally and the tiebreaker is missing, the same person can appear on two pages
while somebody else appears on none.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.saml_harness import ConsoleUsers

pytestmark = pytest.mark.integration


def names(client: TestClient, console: ConsoleUsers, query: str) -> list[str]:
    response = client.get(f"/api/users?limit=50&{query}", headers=console.as_user(console.admin))
    assert response.status_code == 200, response.text
    return [row["display_name"] for row in response.json()["items"]]


def test_the_default_order_is_by_name(db_client: TestClient, console: ConsoleUsers) -> None:
    assert names(db_client, console, "sort=display_name") == names(db_client, console, "")


def test_ascending_and_descending_are_opposites(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    up = names(db_client, console, "sort=display_name&order=asc")
    down = names(db_client, console, "sort=display_name&order=desc")
    assert up == sorted(up)
    assert down == sorted(down, reverse=True)


def test_another_column_sorts_by_that_column(db_client: TestClient, console: ConsoleUsers) -> None:
    """Asking for a different column really orders by it, not just by name."""
    response = db_client.get(
        "/api/users?limit=50&sort=user_name&order=desc",
        headers=console.as_user(console.admin),
    )
    logins = [row["user_name"] for row in response.json()["items"]]
    assert logins == sorted(logins, reverse=True)


def test_paging_does_not_repeat_anybody(db_client: TestClient, console: ConsoleUsers) -> None:
    """Two people with the same name still get a stable order, from the id tiebreak."""
    headers = console.as_user(console.admin)
    first = db_client.get("/api/users?sort=display_name&limit=25&offset=0", headers=headers)
    second = db_client.get("/api/users?sort=display_name&limit=25&offset=25", headers=headers)

    first_ids = {row["id"] for row in first.json()["items"]}
    second_ids = {row["id"] for row in second.json()["items"]}
    assert first_ids
    assert first_ids.isdisjoint(second_ids)


def test_a_column_we_do_not_sort_by_is_refused(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    """An allowlist, so a query parameter cannot name any column it likes."""
    response = db_client.get(
        "/api/users?sort=password_hash", headers=console.as_user(console.admin)
    )
    assert response.status_code == 422
    assert "password_hash" in response.text


def test_a_direction_we_do_not_understand_is_refused(
    db_client: TestClient, console: ConsoleUsers
) -> None:
    response = db_client.get(
        "/api/users?sort=display_name&order=sideways", headers=console.as_user(console.admin)
    )
    assert response.status_code == 422
