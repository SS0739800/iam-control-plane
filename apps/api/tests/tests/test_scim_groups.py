"""Tests for /scim/v2/Groups and the discovery documents.

Membership is what these are about. The test that matters most is the pair
covering ``add`` against ``replace``: add puts somebody in and leaves everyone
else alone, replace sets the list to exactly what arrived. Treating an add as a
replace empties groups, and does it quietly — the request succeeds and the
members are simply gone.

These need Postgres and skip without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import IdentitySource
from iam.models.group import Group
from iam.scim.constants import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_SCHEMA,
    SCIM_MEDIA_TYPE,
    USER_SCHEMA,
)
from tests.support import ScimCaller, run_db

pytestmark = pytest.mark.integration

USERS = "/scim/v2/Users"
GROUPS = "/scim/v2/Groups"


def make_person(client: TestClient, caller: ScimCaller, user_name: str) -> str:
    response = client.post(
        USERS,
        json={"userName": user_name, "emails": [{"value": user_name, "primary": True}]},
        headers=caller.headers,
    )
    assert response.status_code == 201, response.text[:300]
    return str(response.json()["id"])


def make_group(
    client: TestClient, caller: ScimCaller, members: list[str] | None = None
) -> dict[str, Any]:
    response = client.post(
        GROUPS,
        json={
            "schemas": [GROUP_SCHEMA],
            "displayName": caller.group_name,
            "members": [{"value": member} for member in (members or [])],
        },
        headers=caller.headers,
    )
    assert response.status_code == 201, response.text[:300]
    created: dict[str, Any] = response.json()
    return created


def patch(client: TestClient, caller: ScimCaller, group_id: str, *ops: dict[str, Any]) -> Any:
    return client.patch(
        f"{GROUPS}/{group_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": list(ops),
        },
        headers=caller.headers,
    )


# ---------------------------------------------------------------- discovery


def test_what_we_claim_to_support_is_what_we_do(db_client: TestClient, caller: ScimCaller) -> None:
    """A provider plans its whole sync around this document. Overstating support
    doesn't get us more functionality — it gets a provider confidently doing something we refuse.
    """
    document = db_client.get("/scim/v2/ServiceProviderConfig", headers=caller.headers).json()

    assert document["patch"]["supported"] is True
    assert document["filter"]["supported"] is True
    assert document["bulk"]["supported"] is False
    assert document["sort"]["supported"] is False


def test_discovery_needs_a_token_like_everything_else(db_client: TestClient) -> None:
    assert db_client.get("/scim/v2/ServiceProviderConfig").status_code == 401
    assert db_client.get("/scim/v2/ResourceTypes").status_code == 401
    assert db_client.get("/scim/v2/Schemas").status_code == 401


def test_the_resource_types_are_the_ones_we_serve(
    db_client: TestClient, caller: ScimCaller
) -> None:
    document = db_client.get("/scim/v2/ResourceTypes", headers=caller.headers).json()
    names = {resource["name"] for resource in document["Resources"]}

    assert names == {"User", "Group"}


def test_the_schemas_say_group_membership_is_read_only_on_a_person(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The load-bearing line in that document: it is how a provider is told to
    write membership on the group rather than on the person."""
    document = db_client.get("/scim/v2/Schemas", headers=caller.headers).json()
    user_schema = next(s for s in document["Resources"] if s["id"] == USER_SCHEMA)
    groups = next(a for a in user_schema["attributes"] if a["name"] == "groups")

    assert groups["mutability"] == "readOnly"


def test_the_enterprise_extension_is_advertised(db_client: TestClient, caller: ScimCaller) -> None:
    document = db_client.get("/scim/v2/Schemas", headers=caller.headers).json()

    assert any(s["id"] == ENTERPRISE_USER_SCHEMA for s in document["Resources"])


def test_discovery_comes_back_as_scim_json(db_client: TestClient, caller: ScimCaller) -> None:
    response = db_client.get("/scim/v2/ServiceProviderConfig", headers=caller.headers)

    assert response.headers["content-type"].startswith(SCIM_MEDIA_TYPE)


# ------------------------------------------------------------ making groups


def test_creating_a_group_with_members(db_client: TestClient, caller: ScimCaller) -> None:
    person = make_person(db_client, caller, caller.user_name)

    group = make_group(db_client, caller, [person])

    assert group["displayName"] == caller.group_name
    assert [member["value"] for member in group["members"]] == [person]


def test_a_group_is_recorded_as_scim_managed(db_client: TestClient, caller: ScimCaller) -> None:
    make_group(db_client, caller)

    async def work(session: AsyncSession) -> Group | None:
        found: Group | None = await session.scalar(
            select(Group).where(Group.name == caller.group_name)
        )
        return found

    stored = run_db(work)
    assert stored is not None
    assert stored.source is IdentitySource.SCIM


def test_two_groups_cannot_share_a_name(db_client: TestClient, caller: ScimCaller) -> None:
    make_group(db_client, caller)

    again = db_client.post(GROUPS, json={"displayName": caller.group_name}, headers=caller.headers)

    assert again.status_code == 409
    assert again.json()["scimType"] == "uniqueness"


def test_a_group_needs_a_name(db_client: TestClient, caller: ScimCaller) -> None:
    response = db_client.post(GROUPS, json={"displayName": "   "}, headers=caller.headers)

    assert response.status_code == 400


def test_finding_a_group_by_name(db_client: TestClient, caller: ScimCaller) -> None:
    make_group(db_client, caller)

    response = db_client.get(
        GROUPS, params={"filter": f'displayName eq "{caller.group_name}"'}, headers=caller.headers
    )

    assert response.json()["totalResults"] == 1


def test_a_group_that_is_not_there(db_client: TestClient, caller: ScimCaller) -> None:
    assert db_client.get(f"{GROUPS}/{uuid.uuid4()}", headers=caller.headers).status_code == 404
    assert db_client.get(f"{GROUPS}/not-a-uuid", headers=caller.headers).status_code == 404


# ------------------------------------------------------------- membership


def test_add_puts_somebody_in_without_removing_anybody(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Half of the pair that matters. Add is not replace."""
    first = make_person(db_client, caller, caller.user_name)
    second = make_person(db_client, caller, caller.other_user_name)
    group = make_group(db_client, caller, [first])

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "add", "path": "members", "value": [{"value": second}]},
    )

    assert {member["value"] for member in response.json()["members"]} == {first, second}


def test_replace_sets_the_membership_to_exactly_what_arrived(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The other half. Replace removes anybody not in the list, which is what it
    means and why it must never be reached by a request that said add."""
    first = make_person(db_client, caller, caller.user_name)
    second = make_person(db_client, caller, caller.other_user_name)
    group = make_group(db_client, caller, [first, second])

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "replace", "path": "members", "value": [{"value": first}]},
    )

    assert [member["value"] for member in response.json()["members"]] == [first]


def test_removing_one_person_by_id(db_client: TestClient, caller: ScimCaller) -> None:
    """The path form a provider sends when somebody leaves a team."""
    first = make_person(db_client, caller, caller.user_name)
    second = make_person(db_client, caller, caller.other_user_name)
    group = make_group(db_client, caller, [first, second])

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "remove", "path": f'members[value eq "{first}"]'},
    )

    assert [member["value"] for member in response.json()["members"]] == [second]


def test_removing_with_no_ids_clears_the_group(db_client: TestClient, caller: ScimCaller) -> None:
    """What a provider means when it empties a group. The spec allows it."""
    first = make_person(db_client, caller, caller.user_name)
    group = make_group(db_client, caller, [first])

    response = patch(db_client, caller, str(group["id"]), {"op": "remove", "path": "members"})

    assert response.json()["members"] == []


def test_adding_the_same_person_twice_is_harmless(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Providers re-send during a full sync and assume repeating themselves is safe."""
    person = make_person(db_client, caller, caller.user_name)
    group = make_group(db_client, caller, [person])

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "add", "path": "members", "value": [{"value": person}]},
    )

    assert len(response.json()["members"]) == 1


def test_a_member_who_does_not_exist_is_skipped_not_fatal(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """One stale id in a list of two hundred should not lose the other 199."""
    person = make_person(db_client, caller, caller.user_name)
    group = make_group(db_client, caller)

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {
            "op": "add",
            "path": "members",
            "value": [{"value": person}, {"value": str(uuid.uuid4())}],
        },
    )

    assert response.status_code == 200
    assert [member["value"] for member in response.json()["members"]] == [person]


def test_a_member_id_that_is_not_an_id_is_skipped(
    db_client: TestClient, caller: ScimCaller
) -> None:
    group = make_group(db_client, caller)

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "add", "path": "members", "value": [{"value": "not-a-uuid"}]},
    )

    assert response.status_code == 200
    assert response.json()["members"] == []


def test_the_person_sees_the_group_they_are_in(db_client: TestClient, caller: ScimCaller) -> None:
    """Read-only on that side, and the reflection has to actually work."""
    person = make_person(db_client, caller, caller.user_name)
    make_group(db_client, caller, [person])

    document = db_client.get(f"{USERS}/{person}", headers=caller.headers).json()

    assert [group["display"] for group in document["groups"]] == [caller.group_name]


def test_a_patch_path_we_do_not_support_is_refused(
    db_client: TestClient, caller: ScimCaller
) -> None:
    group = make_group(db_client, caller)

    response = patch(
        db_client, caller, str(group["id"]), {"op": "replace", "path": "nickname", "value": "x"}
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidPath"


# --------------------------------------------------------------- renaming


def test_renaming_a_group(db_client: TestClient, caller: ScimCaller) -> None:
    group = make_group(db_client, caller)

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "replace", "path": "displayName", "value": f"{caller.group_name} renamed"},
    )

    assert response.json()["displayName"] == f"{caller.group_name} renamed"


def test_the_pathless_rename_entra_sends(db_client: TestClient, caller: ScimCaller) -> None:
    group = make_group(db_client, caller)

    response = patch(
        db_client,
        caller,
        str(group["id"]),
        {"op": "Replace", "value": {"displayName": f"{caller.group_name} again"}},
    )

    assert response.json()["displayName"] == f"{caller.group_name} again"


# ----------------------------------------------------------------- removal


def test_put_replaces_the_membership_wholesale(db_client: TestClient, caller: ScimCaller) -> None:
    """PUT means replace, members included."""
    first = make_person(db_client, caller, caller.user_name)
    second = make_person(db_client, caller, caller.other_user_name)
    group = make_group(db_client, caller, [first, second])

    response = db_client.put(
        f"{GROUPS}/{group['id']}",
        json={"displayName": caller.group_name, "members": [{"value": second}]},
        headers=caller.headers,
    )

    assert [member["value"] for member in response.json()["members"]] == [second]


def test_deleting_a_group_keeps_the_people(db_client: TestClient, caller: ScimCaller) -> None:
    """A group is a container, not somebody's record. Deleting it takes the
    membership rows and nothing else."""
    person = make_person(db_client, caller, caller.user_name)
    group = make_group(db_client, caller, [person])

    assert db_client.delete(f"{GROUPS}/{group['id']}", headers=caller.headers).status_code == 204

    assert db_client.get(f"{USERS}/{person}", headers=caller.headers).status_code == 200
    assert db_client.get(f"{GROUPS}/{group['id']}", headers=caller.headers).status_code == 404
