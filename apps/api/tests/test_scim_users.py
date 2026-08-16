"""Tests for /scim/v2/Users — the provider writing people into the directory.

These need Postgres and skip without IAM_TEST_DATABASE_URL.

The documents are shaped the way real providers send them, including Entra's
pathless PATCH and authentik's enterprise extension. The two tests worth reading
first are the one that says a deactivation ends somebody's sessions, and the one
that says SCIM cannot set what a person is allowed to do in this console.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.models.enums import IdentitySource, PlatformRole
from iam.models.saml import SamlSession
from iam.models.scim import ScimClient
from iam.models.user import User
from iam.scim.constants import ENTERPRISE_USER_SCHEMA, SCIM_MEDIA_TYPE
from tests.support import ScimCaller, run_db

pytestmark = pytest.mark.integration

USERS = "/scim/v2/Users"


def body(caller: ScimCaller, **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": caller.user_name,
        "name": {"givenName": "Scim", "familyName": "Tester"},
        "emails": [{"value": caller.user_name, "primary": True}],
        "externalId": f"ak-{caller.suffix}",
        "active": True,
    }
    document.update(overrides)
    return document


def create(client: TestClient, caller: ScimCaller, **overrides: object) -> dict[str, Any]:
    response = client.post(USERS, json=body(caller, **overrides), headers=caller.headers)
    assert response.status_code == 201, response.text[:400]
    created: dict[str, object] = response.json()
    return created


def fetch_user(user_name: str) -> User | None:
    async def work(session: AsyncSession) -> User | None:
        found: User | None = await session.scalar(select(User).where(User.user_name == user_name))
        return found

    return run_db(work)


# ----------------------------------------------------------------- the token


def test_no_token_is_refused_in_scim_shape(db_client: TestClient) -> None:
    """A provider reading FastAPI's {"detail": ...} learns nothing it can act on."""
    response = db_client.get(USERS)

    assert response.status_code == 401
    assert response.headers["content-type"].startswith(SCIM_MEDIA_TYPE)
    assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert response.json()["status"] == "401"


def test_a_token_nobody_issued_is_refused(db_client: TestClient) -> None:
    response = db_client.get(USERS, headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


def test_the_scheme_is_case_insensitive(db_client: TestClient, caller: ScimCaller) -> None:
    """RFC 7235 says so, and providers send both spellings."""
    response = db_client.get(USERS, headers={"Authorization": f"bearer {caller.token}"})

    assert response.status_code == 200


def test_a_disabled_client_stops_working(db_client: TestClient, caller: ScimCaller) -> None:
    """Turning the sync off has to actually turn it off."""

    async def disable(session: AsyncSession) -> None:
        client = await session.scalar(select(ScimClient).where(ScimClient.name == caller.name))
        assert client is not None
        client.enabled = False

    run_db(disable)

    assert db_client.get(USERS, headers=caller.headers).status_code == 401


def test_a_revoked_client_stops_working(db_client: TestClient, caller: ScimCaller) -> None:
    async def revoke(session: AsyncSession) -> None:
        client = await session.scalar(select(ScimClient).where(ScimClient.name == caller.name))
        assert client is not None
        client.revoked_at = dt.datetime.now(dt.UTC)
        client.revoked_reason = "test"

    run_db(revoke)

    assert db_client.get(USERS, headers=caller.headers).status_code == 401


def test_an_unknown_and_a_revoked_token_are_told_apart_only_in_the_log(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Both answer the same thing. Saying "that token was revoked" out loud tells
    somebody holding a list of candidates which ones were once real."""

    async def revoke(session: AsyncSession) -> None:
        client = await session.scalar(select(ScimClient).where(ScimClient.name == caller.name))
        assert client is not None
        client.revoked_at = dt.datetime.now(dt.UTC)

    run_db(revoke)

    revoked = db_client.get(USERS, headers=caller.headers)
    unknown = db_client.get(USERS, headers={"Authorization": "Bearer nope"})

    assert revoked.json()["detail"] == unknown.json()["detail"]


# ------------------------------------------------------------ finding people


def test_the_list_comes_back_in_scims_envelope(db_client: TestClient, caller: ScimCaller) -> None:
    response = db_client.get(USERS, params={"count": 2}, headers=caller.headers)
    document = response.json()

    assert document["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert document["startIndex"] == 1
    assert document["itemsPerPage"] == len(document["Resources"])
    assert document["totalResults"] >= len(document["Resources"])


def test_paging_is_one_based(db_client: TestClient, caller: ScimCaller) -> None:
    """startIndex 1 is the first record, not the second.

    Off by one here either skips whoever is first in the directory or makes a
    provider request the same page forever. The test makes its own two rows
    rather than assuming the database already has any.
    """
    create(db_client, caller)
    create(db_client, caller, userName=caller.other_user_name, externalId=None)

    both = db_client.get(USERS, params={"count": 2}, headers=caller.headers).json()
    assert len(both["Resources"]) == 2, "need two rows to page over"

    first = db_client.get(USERS, params={"count": 1, "startIndex": 1}, headers=caller.headers)
    second = db_client.get(USERS, params={"count": 1, "startIndex": 2}, headers=caller.headers)

    assert first.json()["startIndex"] == 1
    assert first.json()["Resources"][0]["id"] == both["Resources"][0]["id"]
    assert second.json()["startIndex"] == 2
    assert second.json()["Resources"][0]["id"] == both["Resources"][1]["id"]


def test_asking_past_the_end_returns_nothing_rather_than_wrapping(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """A provider walking pages has to be able to tell when it has finished."""
    total = db_client.get(USERS, params={"count": 1}, headers=caller.headers).json()["totalResults"]

    response = db_client.get(
        USERS, params={"count": 5, "startIndex": total + 100}, headers=caller.headers
    )

    assert response.json()["Resources"] == []
    assert response.json()["itemsPerPage"] == 0


def test_the_question_a_provider_asks_before_creating(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """ "Do you already have this one?" — a single eq on userName."""
    before = db_client.get(
        USERS, params={"filter": f'userName eq "{caller.user_name}"'}, headers=caller.headers
    )
    assert before.json()["totalResults"] == 0

    create(db_client, caller)

    after = db_client.get(
        USERS, params={"filter": f'userName eq "{caller.user_name}"'}, headers=caller.headers
    )
    assert after.json()["totalResults"] == 1


def test_a_username_matches_whatever_case_it_was_sent_in(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Providers are not consistent about the case of an email address, and
    matching exactly would create a second account for the same person."""
    create(db_client, caller)

    response = db_client.get(
        USERS,
        params={"filter": f'userName eq "{caller.user_name.upper()}"'},
        headers=caller.headers,
    )

    assert response.json()["totalResults"] == 1


def test_a_filter_we_cannot_read_is_an_error_not_everybody(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The dangerous one. Answering an unparseable filter with the whole directory
    hands the provider somebody else's account to write to."""
    response = db_client.get(
        USERS, params={"filter": 'userName eq "a" and active eq true'}, headers=caller.headers
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidFilter"


def test_asking_for_somebody_who_is_not_there(db_client: TestClient, caller: ScimCaller) -> None:
    response = db_client.get(f"{USERS}/{uuid.uuid4()}", headers=caller.headers)

    assert response.status_code == 404


def test_an_id_that_could_never_exist_is_a_404_not_a_crash(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The id is whatever the provider put in the URL, so a malformed one has to
    answer rather than raise on the UUID parse."""
    response = db_client.get(f"{USERS}/not-a-uuid", headers=caller.headers)

    assert response.status_code == 404


# -------------------------------------------------------------- creating them


def test_creating_somebody_stores_what_the_provider_sent(
    db_client: TestClient, caller: ScimCaller
) -> None:
    document = create(
        db_client,
        caller,
        **{ENTERPRISE_USER_SCHEMA: {"department": "Engineering", "employeeNumber": "E-99"}},
    )

    assert document["userName"] == caller.user_name
    assert document["meta"]["resourceType"] == "User"

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.department == "Engineering"
    assert stored.employee_number == "E-99"
    assert stored.source is IdentitySource.SCIM


def test_creating_the_same_person_twice_says_uniqueness(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The code a provider reads to mean "already there, update instead". A bare
    400 makes it report a failed sync forever over somebody who exists."""
    create(db_client, caller)

    again = db_client.post(USERS, json=body(caller), headers=caller.headers)

    assert again.status_code == 409
    assert again.json()["scimType"] == "uniqueness"


def test_two_people_cannot_share_an_external_id(db_client: TestClient, caller: ScimCaller) -> None:
    create(db_client, caller)

    clash = db_client.post(
        USERS,
        json=body(caller, userName=f"other.{caller.suffix}@demo.local"),
        headers=caller.headers,
    )

    assert clash.status_code == 409
    assert clash.json()["scimType"] == "uniqueness"


def test_a_provider_cannot_decide_what_somebody_may_do_here(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The important one. Nothing upstream should be able to grant itself an admin
    in this console by editing a directory record."""
    create(db_client, caller, platform_role="admin", source="manual")

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.platform_role is PlatformRole.EMPLOYEE


def test_creating_somebody_is_recorded_against_the_client_not_the_person(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """ "authentik created this account at 02:14" is the sentence somebody needs
    later, and it isn't available if this is logged as the user acting on
    themselves."""
    create(db_client, caller)

    async def work(session: AsyncSession) -> AuditEvent | None:
        found: AuditEvent | None = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.target_label == caller.user_name)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        return found

    event = run_db(work)
    assert event is not None
    assert event.action == "user.created"
    assert caller.name in event.actor_label


# -------------------------------------------------------------- changing them


def test_replacing_does_not_blank_what_the_document_leaves_out(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """A partial resource on PUT must not read as "set the rest to null", or one
    tidy-up sync blanks everybody's department."""
    created = create(db_client, caller, **{ENTERPRISE_USER_SCHEMA: {"department": "Engineering"}})

    db_client.put(
        f"{USERS}/{created['id']}",
        json={"userName": caller.user_name, "displayName": "Renamed", "active": True},
        headers=caller.headers,
    )

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.display_name == "Renamed"
    assert stored.department == "Engineering"


def test_deprovisioning_is_a_patch_of_one_boolean(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """What a leaver actually looks like on the wire."""
    created = create(db_client, caller)

    response = db_client.patch(
        f"{USERS}/{created['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=caller.headers,
    )

    assert response.status_code == 200
    assert response.json()["active"] is False

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.active is False


def test_the_pathless_patch_entra_sends_also_works(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """No path, and the value is a partial resource. Handling only the other shape
    works against authentik and then ignores every deactivation Entra sends."""
    created = create(db_client, caller)

    response = db_client.patch(
        f"{USERS}/{created['id']}",
        json={"Operations": [{"op": "Replace", "value": {"active": False}}]},
        headers=caller.headers,
    )

    assert response.json()["active"] is False


def test_a_patch_path_we_cannot_act_on_is_refused_not_ignored(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """A PATCH that answers 200 and changes nothing tells the provider somebody was
    deactivated when they were not."""
    created = create(db_client, caller)

    response = db_client.patch(
        f"{USERS}/{created['id']}",
        json={"Operations": [{"op": "replace", "path": "nickName", "value": "x"}]},
        headers=caller.headers,
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidPath"


def test_a_login_created_person_becomes_scim_managed_when_the_provider_writes(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Somebody who arrived by logging in is a bare username. Once the directory
    upstream owns them, the console should stop offering to hand-edit fields the
    next sync would overwrite."""

    async def make_jit(session: AsyncSession) -> str:
        person = User(
            user_name=caller.user_name,
            email=caller.user_name,
            display_name="Arrived By Logging In",
            active=True,
            platform_role=PlatformRole.EMPLOYEE,
            source=IdentitySource.JIT,
        )
        session.add(person)
        await session.flush()
        return str(person.id)

    user_id = run_db(make_jit)

    db_client.put(
        f"{USERS}/{user_id}",
        json={"userName": caller.user_name, "displayName": "Now Managed", "active": True},
        headers=caller.headers,
    )

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.source is IdentitySource.SCIM


# ------------------------------------------------------- taking access away


def test_deactivating_ends_every_session_they_have(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """The point of the whole phase. Setting a flag while leaving somebody signed
    in for the next eight hours is the failure this design exists to avoid."""
    created = create(db_client, caller)
    user_id = uuid.UUID(str(created["id"]))

    async def give_them_sessions(session: AsyncSession) -> None:
        for index in range(2):
            session.add(
                SamlSession(
                    token_hash=f"hash-{caller.suffix}-{index}",
                    user_id=user_id,
                    idp_slug="authentik",
                    name_id=f"persistent-{caller.suffix}",
                    name_id_format=None,
                    session_index=f"index-{index}",
                    expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=8),
                )
            )

    run_db(give_them_sessions)

    db_client.patch(
        f"{USERS}/{created['id']}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=caller.headers,
    )

    async def read_sessions(session: AsyncSession) -> list[SamlSession]:
        rows = (
            await session.scalars(select(SamlSession).where(SamlSession.user_id == user_id))
        ).all()
        return list(rows)

    sessions = read_sessions_result = run_db(read_sessions)
    assert len(sessions) == 2
    assert all(row.revoked_at is not None for row in read_sessions_result)
    assert all(row.revoked_reason == "user_deactivated" for row in sessions)


def test_delete_deactivates_and_keeps_the_row(db_client: TestClient, caller: ScimCaller) -> None:
    """A provider sending DELETE means "this person has left". Erasing the record
    of what they had access to is the opposite of what an audit log is for."""
    created = create(db_client, caller)

    response = db_client.delete(f"{USERS}/{created['id']}", headers=caller.headers)

    assert response.status_code == 204

    stored = fetch_user(caller.user_name)
    assert stored is not None
    assert stored.active is False


def test_deleting_twice_is_not_an_error(db_client: TestClient, caller: ScimCaller) -> None:
    """A provider retrying a delete it already sent should not be punished for
    being thorough."""
    created = create(db_client, caller)

    first = db_client.delete(f"{USERS}/{created['id']}", headers=caller.headers)
    second = db_client.delete(f"{USERS}/{created['id']}", headers=caller.headers)

    assert first.status_code == 204
    assert second.status_code == 204


def test_re_sending_an_unchanged_record_writes_no_audit_entry(
    db_client: TestClient, caller: ScimCaller
) -> None:
    """Providers re-send constantly during a full sync. Logging every one would
    bury the changes that matter."""
    created = create(db_client, caller)

    async def newest_id(session: AsyncSession) -> int:
        found = await session.scalar(select(AuditEvent.id).order_by(AuditEvent.id.desc()).limit(1))
        return int(found or 0)

    before = run_db(newest_id)

    db_client.put(f"{USERS}/{created['id']}", json=body(caller), headers=caller.headers)

    assert run_db(newest_id) == before
