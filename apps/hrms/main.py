"""A small HRMS that accepts accounts pushed to it over SCIM.

What this is for
----------------

The identity platform next door can provision outward, and until now there was
nowhere to provision *to*. Its own SCIM server works for tests — and a system pushing
accounts into its own directory proves interoperability while proving nothing about
being useful.

So this is the downstream. Somebody is granted access in the console, and an employee
appears here. They lose it, and the employee is switched off here. That is the whole
point of the platform, and it is not demonstrable without something on the other end.

Deliberately not sharing any code with the platform
--------------------------------------------------

Nothing here imports from ``iam``. Not the SCIM constants, not the models, not the
token helpers — even though copying a few URN strings is mildly annoying.

That is the entire value of this service. Two halves of a protocol that share a
constant agree by construction rather than by conformance, and the interesting bugs
live exactly where two independent readings of a specification differ. If this
imported the platform's mapping code, a wrong attribute name would match itself and
the test would pass.

It also keeps this honest about being third-party: different framework conventions,
different storage, its own bearer token, no shared database.

Storage
-------

SQLite, in a file, with the standard library. No ORM and no migrations, because this
has one table and the point is to be obviously a different system rather than a second
copy of the platform's architecture. Synchronous handlers are fine at this scale and
mean one less thing to explain.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

DATABASE_PATH = os.environ.get("HRMS_DATABASE", "/data/hrms.sqlite3")

SCIM_TOKEN = os.environ.get("HRMS_SCIM_TOKEN", "")
"""The token the platform must present.

No default worth using. Empty means every SCIM request is refused, which is the right
way round: a demo that accepts anything is a demo of nothing.
"""

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

SCIM_MEDIA_TYPE = "application/scim+json"

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    setup()
    yield


app = FastAPI(
    title="Demo HRMS",
    summary="The downstream system the identity platform provisions into",
    docs_url="/docs",
    lifespan=lifespan,
)

bearer = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------- storage


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def setup() -> None:
    """Create the one table.

    Called on startup rather than by a migration tool. One table, no history to
    preserve, and adding Alembic here would be borrowing the platform's shape for no
    reason.
    """
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS employees (
                id            TEXT PRIMARY KEY,
                user_name     TEXT NOT NULL UNIQUE,
                external_id   TEXT,
                display_name  TEXT NOT NULL DEFAULT '',
                given_name    TEXT,
                family_name   TEXT,
                email         TEXT,
                department    TEXT,
                active        INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                raw           TEXT NOT NULL DEFAULT '{}'
            )
            """
        )


def now() -> str:
    return datetime.now(UTC).isoformat()


# ------------------------------------------------------------------- SCIM bits


def scim_error(status_code: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status_code, media_type=SCIM_MEDIA_TYPE)


def require_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> None:
    """Check the bearer token.

    Compared with a plain equality rather than a constant-time compare, and that is a
    real shortcut worth naming: this is a demo downstream, and a timing attack on it
    would win an attacker the ability to write to a fake HR system. The platform's own
    inbound check does it properly.

    Raises:
        HTTPException: 401 if the token is missing, wrong, or none is configured.
    """
    if not SCIM_TOKEN:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="No token is configured here, so nothing is accepted.",
        )
    if credentials is None or credentials.credentials != SCIM_TOKEN:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="That token is not accepted.")


def as_scim(row: sqlite3.Row, *, base_url: str) -> dict[str, Any]:
    """One employee, as SCIM sees them."""
    document: dict[str, Any] = {
        "schemas": [USER_SCHEMA],
        "id": row["id"],
        "userName": row["user_name"],
        "displayName": row["display_name"],
        "active": bool(row["active"]),
        "meta": {
            "resourceType": "User",
            "created": row["created_at"],
            "lastModified": row["updated_at"],
            "location": f"{base_url}/scim/v2/Users/{row['id']}",
        },
    }
    if row["external_id"]:
        document["externalId"] = row["external_id"]
    if row["email"]:
        document["emails"] = [{"value": row["email"], "type": "work", "primary": True}]
    if row["given_name"] or row["family_name"]:
        document["name"] = {
            key: value
            for key, value in (
                ("givenName", row["given_name"]),
                ("familyName", row["family_name"]),
            )
            if value
        }
    if row["department"]:
        document["schemas"] = [USER_SCHEMA, ENTERPRISE_SCHEMA]
        document[ENTERPRISE_SCHEMA] = {"department": row["department"]}
    return document


def read_incoming(document: dict[str, Any]) -> dict[str, Any]:
    """Pull the fields we keep out of a SCIM document.

    Written from the specification rather than from the platform's mapping code, on
    purpose — see the module docstring. Where the two disagree, that disagreement is
    the thing worth finding.
    """
    emails = document.get("emails") or []
    primary = next(
        (entry for entry in emails if isinstance(entry, dict) and entry.get("primary")),
        emails[0] if emails and isinstance(emails[0], dict) else None,
    )
    name = document.get("name") or {}
    enterprise = document.get(ENTERPRISE_SCHEMA) or {}

    return {
        "user_name": document.get("userName") or "",
        "external_id": document.get("externalId"),
        "display_name": document.get("displayName") or "",
        "given_name": name.get("givenName"),
        "family_name": name.get("familyName"),
        "email": (primary or {}).get("value"),
        "department": enterprise.get("department"),
        # `active` defaults to true when absent, which the spec says and which matters:
        # a create that omits it is somebody who should be able to work.
        "active": 1 if document.get("active", True) else 0,
    }


def base_of(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ------------------------------------------------------------- SCIM endpoints


@app.get("/scim/v2/ServiceProviderConfig", dependencies=[Depends(require_token)])
def service_provider_config(request: Request) -> JSONResponse:
    """What this system supports.

    Answered honestly, which for this one means saying filter support is limited. The
    platform reads this before it does anything, and a downstream that overstates its
    abilities gets confidently sent things it cannot handle.
    """
    return JSONResponse(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": f"{base_of(request)}/docs",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "primary": True,
                }
            ],
        },
        media_type=SCIM_MEDIA_TYPE,
    )


@app.get("/scim/v2/Users", dependencies=[Depends(require_token)])
def list_users(
    request: Request,
    filter: str | None = Query(default=None),  # noqa: A002 — the SCIM parameter name
    count: int = Query(default=100, ge=1, le=200),
) -> JSONResponse:
    """List or search employees.

    Only ``userName eq "value"`` is understood, which is the one filter a provisioning
    client actually sends when it is looking for an account it has lost track of.
    Anything else returns everybody rather than pretending to have filtered — a silent
    wrong answer here would make the platform link somebody to the wrong account.
    """
    wanted: str | None = None
    if filter:
        cleaned = filter.strip()
        if cleaned.lower().startswith("username eq"):
            wanted = cleaned[len("username eq") :].strip().strip('"')

    with connect() as connection:
        if wanted is not None:
            rows = connection.execute(
                "SELECT * FROM employees WHERE user_name = ? LIMIT ?", (wanted, count)
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM employees ORDER BY user_name LIMIT ?", (count,)
            ).fetchall()

    base = base_of(request)
    return JSONResponse(
        {
            "schemas": [LIST_SCHEMA],
            "totalResults": len(rows),
            "startIndex": 1,
            "itemsPerPage": len(rows),
            "Resources": [as_scim(row, base_url=base) for row in rows],
        },
        media_type=SCIM_MEDIA_TYPE,
    )


@app.get("/scim/v2/Users/{employee_id}", dependencies=[Depends(require_token)])
def get_user(employee_id: str, request: Request) -> JSONResponse:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()

    if row is None:
        return scim_error(404, f"No employee with id {employee_id}.")
    return JSONResponse(as_scim(row, base_url=base_of(request)), media_type=SCIM_MEDIA_TYPE)


@app.post("/scim/v2/Users", status_code=201, dependencies=[Depends(require_token)])
async def create_user(request: Request) -> JSONResponse:
    """Take on a new employee.

    A duplicate userName is a 409 with scimType uniqueness, which is what lets the
    platform tell "already here, adopt it" apart from "broken, retry later". Getting
    that wrong on this side would make onboarding an existing system fail forever on
    the other.
    """
    document = json.loads(await request.body())
    fields = read_incoming(document)

    if not fields["user_name"]:
        return scim_error(400, "userName is required.", "invalidValue")

    with connect() as connection:
        clash = connection.execute(
            "SELECT id FROM employees WHERE user_name = ?", (fields["user_name"],)
        ).fetchone()
        if clash is not None:
            return scim_error(
                409, f"userName {fields['user_name']!r} already exists here.", "uniqueness"
            )

        employee_id = str(uuid.uuid4())
        timestamp = now()
        connection.execute(
            """
            INSERT INTO employees (
                id, user_name, external_id, display_name, given_name, family_name,
                email, department, active, created_at, updated_at, raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                employee_id,
                fields["user_name"],
                fields["external_id"],
                fields["display_name"],
                fields["given_name"],
                fields["family_name"],
                fields["email"],
                fields["department"],
                fields["active"],
                timestamp,
                timestamp,
                json.dumps(document),
            ),
        )
        row = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()

    return JSONResponse(
        as_scim(row, base_url=base_of(request)), status_code=201, media_type=SCIM_MEDIA_TYPE
    )


@app.put("/scim/v2/Users/{employee_id}", dependencies=[Depends(require_token)])
async def replace_user(employee_id: str, request: Request) -> JSONResponse:
    """Replace an employee's record with what the platform sent.

    PUT means replace, so anything absent from the document is cleared. That is what
    the verb means and why the platform uses PATCH to deactivate somebody instead —
    a PUT there would wipe every field the platform does not track.
    """
    document = json.loads(await request.body())
    fields = read_incoming(document)

    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()
        if row is None:
            return scim_error(404, f"No employee with id {employee_id}.")

        connection.execute(
            """
            UPDATE employees SET
                user_name = ?, external_id = ?, display_name = ?, given_name = ?,
                family_name = ?, email = ?, department = ?, active = ?,
                updated_at = ?, raw = ?
            WHERE id = ?
            """,
            (
                fields["user_name"] or row["user_name"],
                fields["external_id"],
                fields["display_name"],
                fields["given_name"],
                fields["family_name"],
                fields["email"],
                fields["department"],
                fields["active"],
                now(),
                json.dumps(document),
                employee_id,
            ),
        )
        updated = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()

    return JSONResponse(as_scim(updated, base_url=base_of(request)), media_type=SCIM_MEDIA_TYPE)


@app.patch("/scim/v2/Users/{employee_id}", dependencies=[Depends(require_token)])
async def patch_user(employee_id: str, request: Request) -> JSONResponse:
    """Change part of an employee's record.

    This is how somebody leaving arrives: ``replace active false``. The whole point of
    supporting PATCH is that it touches only what was named, so a leaver loses their
    access and keeps their record.
    """
    document = json.loads(await request.body())
    operations = document.get("Operations") or []

    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()
        if row is None:
            return scim_error(404, f"No employee with id {employee_id}.")

        changes: dict[str, Any] = {}
        for operation in operations:
            if str(operation.get("op", "")).lower() not in ("replace", "add"):
                return scim_error(
                    400, f"{operation.get('op')!r} is not supported here.", "invalidSyntax"
                )

            path = str(operation.get("path") or "").strip().lower()
            value = operation.get("value")

            if path == "active":
                changes["active"] = 1 if value else 0
            elif path == "displayname":
                changes["display_name"] = value
            elif path == "department":
                changes["department"] = value
            elif not path and isinstance(value, dict):
                # A pathless operation carrying a partial resource, which is what some
                # providers send. Only the fields we know about are taken.
                if "active" in value:
                    changes["active"] = 1 if value["active"] else 0
                if "displayName" in value:
                    changes["display_name"] = value["displayName"]
            else:
                return scim_error(
                    400,
                    f"Cannot patch {operation.get('path')!r} here. Supported: active, "
                    "displayName, department.",
                    "invalidPath",
                )

        if changes:
            assignments = ", ".join(f"{column} = ?" for column in changes)
            connection.execute(
                f"UPDATE employees SET {assignments}, updated_at = ? WHERE id = ?",  # noqa: S608
                (*changes.values(), now(), employee_id),
            )

        updated = connection.execute(
            "SELECT * FROM employees WHERE id = ?", (employee_id,)
        ).fetchone()

    return JSONResponse(as_scim(updated, base_url=base_of(request)), media_type=SCIM_MEDIA_TYPE)


# --------------------------------------------------------------- the human bit


@app.get("/", response_class=HTMLResponse)
def staff_directory() -> HTMLResponse:
    """Who works here, according to whoever has been provisioning us.

    No login. This is a demo downstream and the page exists so somebody can watch an
    account appear and switch off — putting a login in front of it would make the
    thing it is meant to demonstrate harder to see.
    """
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM employees ORDER BY active DESC, user_name"
        ).fetchall()

    working = sum(1 for row in rows if row["active"])
    left = len(rows) - working

    def cell(row: sqlite3.Row) -> str:
        badge = (
            '<span class="on">active</span>'
            if row["active"]
            else '<span class="off">no longer here</span>'
        )
        return (
            "<tr>"
            f"<td>{row['display_name'] or '—'}</td>"
            f"<td class='mono'>{row['user_name']}</td>"
            f"<td>{row['department'] or '—'}</td>"
            f"<td>{badge}</td>"
            f"<td class='mono small'>{row['external_id'] or '—'}</td>"
            "</tr>"
        )

    body = "".join(cell(row) for row in rows) or (
        "<tr><td colspan='5' class='empty'>Nobody has been provisioned here yet. "
        "Grant somebody access to this application in the identity console, then run "
        "a sync.</td></tr>"
    )

    return HTMLResponse(
        f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Demo HRMS</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
        color: #1e293b; }}
 h1 {{ font-size: 1.4rem; margin-bottom: .25rem; }}
 p.lede {{ color: #64748b; margin-top: 0; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
 th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #e2e8f0; }}
 th {{ font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; color: #64748b; }}
 .mono {{ font-family: ui-monospace, monospace; font-size: .85rem; }}
 .small {{ font-size: .72rem; color: #94a3b8; }}
 .on {{ color: #047857; }} .off {{ color: #b91c1c; }}
 .empty {{ color: #64748b; padding: 2rem .6rem; }}
 .counts {{ margin-top: 1rem; font-size: .9rem; color: #475569; }}
 footer {{ margin-top: 2rem; font-size: .8rem; color: #94a3b8; }}
</style></head>
<body>
  <h1>Demo HRMS</h1>
  <p class="lede">A downstream system. Everybody below was created by the identity
     platform pushing accounts here over SCIM — nobody was added by hand.</p>
  <p class="counts">{working} working here, {left} no longer here.</p>
  <table>
    <thead><tr><th>Name</th><th>Login</th><th>Department</th><th>Status</th>
      <th>Their id upstream</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
  <footer>
    Nobody is deleted here. Somebody who leaves is switched off, so their record
    survives — which is why the identity platform sends <code>active: false</code>
    rather than DELETE.
  </footer>
</body></html>"""
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
