"""Drive a whole joiner-mover-leaver through to the HRMS and back.

    python -m scripts.smoke_provisioning

Needs the stack up, the HRMS included:

    docker compose up -d api web db hrms

What it proves, in order: an entitled person gets an account in a system that
shares no code with us; a change to them reaches that system; somebody leaving
has their account switched off rather than deleted; and a rehire gets their
old account back rather than a second one.

The unit tests reach the HRMS in-process through an ASGI transport (no socket,
no container, no network), so this is the only check for whether two
containers can actually talk to each other — a wrong hostname or a missing
token only shows up here.

The leaver step marks the person inactive rather than removing a direct
assignment, since access to the HRMS in the seeded data comes entirely from
group membership — removing a direct grant would leave them still entitled
through their department and deactivate nobody.

Puts the person back the way it found them and removes the target it
registered. The employee row in the HRMS is left behind, since there's no
delete to call and a former employee still on file is the correct end state.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

import httpx

CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8080")
HRMS = os.environ.get("HRMS_URL", "http://localhost:8090")

# What the api container calls the HRMS. Not localhost:8090 — that is the port mapped
# onto the host, and from inside a container it points at the container itself.
TARGET_URL = os.environ.get("HRMS_SCIM_URL", "http://hrms:8000/scim/v2")
TOKEN = os.environ.get("HRMS_SCIM_TOKEN", "dev-only-hrms-scim-token")

APPLICATION_SLUG = "hrms"


def step(message: str) -> None:
    print(f"\n=== {message}")


def ok(response: httpx.Response, expected: int | tuple[int, ...] = 200) -> Any:
    wanted = expected if isinstance(expected, tuple) else (expected,)
    assert response.status_code in wanted, (
        f"{response.request.method} {response.request.url} -> "
        f"HTTP {response.status_code}: {response.text[:500]}"
    )
    return response.json() if response.content else None


class Console:
    """The admin console API, as an admin.

    Authenticated by the development actor rather than a SAML session — the
    login path has its own smoke script.
    """

    def __init__(self) -> None:
        self.http = httpx.Client(base_url=CONSOLE, timeout=300, follow_redirects=False)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.get(path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.post(path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.patch(path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.delete(path, **kwargs)


def hrms_employees() -> dict[str, dict[str, Any]]:
    """Ask the HRMS directly, keyed by login.

    Reads from the HRMS rather than our own link rows, which only say what we
    believe happened.
    """
    response = httpx.get(
        f"{HRMS}/scim/v2/Users",
        headers={"Authorization": f"Bearer {TOKEN}"},
        params={"count": 200},
        timeout=60,
    )
    body = ok(response)
    return {entry["userName"]: entry for entry in body["Resources"]}


def one_employee(user_name: str) -> dict[str, Any] | None:
    """One employee, by login, straight from the HRMS."""
    response = httpx.get(
        f"{HRMS}/scim/v2/Users",
        headers={"Authorization": f"Bearer {TOKEN}"},
        params={"filter": f'userName eq "{user_name}"'},
        timeout=30,
    )
    found = ok(response)["Resources"]
    return found[0] if found else None


def sync(console: Console, target_id: str) -> dict[str, Any]:
    """Run one sync, and say how long it took.

    Timing printed since there's no background worker — a sync runs inside the
    request that asked for it, which is slow on a first run against a large
    directory.
    """
    started = time.monotonic()
    run = ok(console.post(f"/api/provisioning/targets/{target_id}/sync"))
    took = time.monotonic() - started
    print(
        f"  created {run['created']}, adopted {run['adopted']}, updated {run['updated']}, "
        f"deactivated {run['deactivated']}, reactivated {run['reactivated']}, "
        f"unchanged {run['unchanged']}, failed {run['failed']}  [{took:.1f}s]"
    )
    if run.get("stopped_early"):
        print(f"  stopped early: {run['stopped_early']}")
    return dict(run)


def main() -> int:
    console = Console()

    step("0. is anything listening")
    health = httpx.get(f"{HRMS}/health", timeout=10)
    print(f"HRMS: HTTP {health.status_code} {health.text}")
    assert health.status_code == 200, "start the HRMS: docker compose up -d hrms"

    applications = ok(console.get("/api/applications"))
    items = applications if isinstance(applications, list) else applications["items"]
    application = next(a for a in items if a["slug"] == APPLICATION_SLUG)
    print(f"application: {application['name']} ({application['id']})")

    step("1. register the HRMS as somewhere we provision into")
    existing = ok(console.get("/api/provisioning/targets"))
    already = next((t for t in existing if t["application_id"] == application["id"]), None)
    if already:
        # One target per application, so re-running rotates rather than adds.
        print(f"already registered, rotating its token: {already['id']}")
        target = ok(
            console.patch(
                f"/api/provisioning/targets/{already['id']}",
                json={"base_url": TARGET_URL, "token": TOKEN, "enabled": True},
            )
        )
    else:
        target = ok(
            console.post(
                "/api/provisioning/targets",
                json={
                    "application_id": application["id"],
                    "base_url": TARGET_URL,
                    "token": TOKEN,
                    "enabled": True,
                },
            ),
            (200, 201),
        )
    target_id = target["id"]
    print(f"target: {target_id} -> {target['base_url']}")
    if target["address_concession"]:
        # Plain HTTP to a private address — a container on the same network.
        # Recorded rather than silently allowed; see ADR 0007.
        print(f"  allowed with a concession: {target['address_concession']}")

    assert TOKEN not in str(target), "the token came back in the response"

    step("2. probe it, before changing anything")
    probe = ok(console.post(f"/api/provisioning/targets/{target_id}/probe"))
    print(f"reachable: {probe['reachable']} - {probe['detail']}")
    assert probe["reachable"], probe["detail"]

    step("3. pick somebody entitled to it")
    users = ok(console.get("/api/users", params={"limit": 200}))
    people = users if isinstance(users, list) else users["items"]
    employees = hrms_employees()

    # Somebody whose department we're allowed to edit. A person who arrived via
    # inbound SCIM has their department owned by that provider, and the console
    # refuses to change it since the next sync would overwrite it anyway.
    editable = [
        p for p in people if p["active"] and p.get("user_name") and p.get("source") != "scim"
    ]
    assert editable, "nobody here has a locally editable department"

    # Prefer somebody with no HRMS account yet, so step 4 is a real joiner
    # rather than a no-op. On a re-run there may not be one.
    person = next(
        (p for p in editable if p["user_name"] not in employees),
        editable[0],
    )
    brand_new = person["user_name"] not in employees
    was_department = person.get("department")
    print(f"person: {person['display_name']} <{person['user_name']}> (source: {person['source']})")
    print(f"  department on file with us: {was_department or '(none)'}")
    print(f"  has an account at the HRMS already: {'no' if brand_new else 'yes'}")

    step("4. sync — the joiner")
    first = sync(console, target_id)
    assert first["ok"], first.get("stopped_early") or "the run did not finish cleanly"
    if brand_new:
        assert first["created"] >= 1, "somebody with no account did not get one"
    if first["created"] > 1:
        # A first run provisions everybody entitled, which on the seeded
        # directory is most of the company.
        print(f"  a first run provisions the whole entitled directory: {first['created']} people")

    hired = one_employee(person["user_name"])
    assert hired is not None, "the HRMS has no such employee"
    print(f"the HRMS now has: {hired['displayName']} ({hired['id']}), active={hired['active']}")
    assert hired["active"] is True
    remote_id = hired["id"]

    step("5. sync again — nothing should happen twice")
    repeat = sync(console, target_id)
    assert repeat["created"] == 0, "a second run created more accounts"
    assert repeat["updated"] == 0, "a second run pushed changes nobody made"

    step("6. move them to another department — the mover")
    moved_to = "Finance" if was_department != "Finance" else "Engineering"
    ok(console.patch(f"/api/users/{person['id']}", json={"department": moved_to}))
    print(f"moved to {moved_to} with us")
    mover = sync(console, target_id)
    assert mover["updated"] >= 1, "the change never left our side"

    enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    after_move = one_employee(person["user_name"])
    assert after_move is not None
    print(f"the HRMS has them in: {(after_move.get(enterprise) or {}).get('department')}")
    assert (after_move.get(enterprise) or {}).get("department") == moved_to

    step("7. they leave — the leaver")
    ok(console.patch(f"/api/users/{person['id']}", json={"active": False}))
    print("marked as having left, with us")
    leaver = sync(console, target_id)
    assert leaver["deactivated"] >= 1, "nobody was switched off"

    gone = one_employee(person["user_name"])
    assert gone is not None, "the record was deleted — it should survive"
    print(f"still on file at the HRMS, switched off: active={gone['active']}")
    assert gone["active"] is False
    assert gone["id"] == remote_id
    # This is why we send PATCH rather than PUT: a leaver keeps their record.
    assert gone["displayName"] == hired["displayName"], "deactivating blanked their name"

    step("8. they come back — the rehire")
    ok(console.patch(f"/api/users/{person['id']}", json={"active": True}))
    rehire = sync(console, target_id)
    assert rehire["created"] == 0, "a rehire made a second account instead of reusing theirs"
    assert rehire["reactivated"] >= 1, "nobody was switched back on"

    back = one_employee(person["user_name"])
    assert back is not None and back["active"] is True
    assert back["id"] == remote_id, "they came back as somebody else"
    print(f"same account as before: {back['id']}")

    step("9. what the console can see about it")
    accounts = ok(console.get(f"/api/provisioning/targets/{target_id}/accounts"))
    rows = accounts if isinstance(accounts, list) else accounts["items"]
    mine = [row for row in rows if row["user_name"] == person["user_name"]]
    for row in mine + rows[:5]:
        print(f"  {row['state']:14} {row['user_name']:34} remote={row['remote_id']}")

    summary = ok(console.get("/api/provisioning/targets"))
    counts = next(t for t in summary if t["id"] == target_id)
    print(
        f"  active {counts['accounts_active']}, pending {counts['accounts_pending']}, "
        f"failed {counts['accounts_failed']}, orphaned {counts['accounts_orphaned']}, "
        f"deprovisioned {counts['accounts_deprovisioned']}"
    )
    assert counts["accounts_failed"] == 0, "something failed to push"

    step("10. put things back")
    ok(
        console.patch(
            f"/api/users/{person['id']}",
            json={"active": True, "department": was_department},
        )
    )
    ok(console.delete(f"/api/provisioning/targets/{target_id}"), (200, 204))
    print("person restored, target removed")

    print(f"\nJoiner, mover, leaver and rehire all reached the HRMS. See {HRMS}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
