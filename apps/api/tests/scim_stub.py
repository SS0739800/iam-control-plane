"""A downstream SCIM server that keeps accounts in a dictionary.

The client's own tests point at our real SCIM server, to prove a real SCIM
2.0 implementation accepts what we send. The sync's tests ask a different
question — does it push the right things to the right people — and pointing
those at our own app makes them fight the database: both sides write audit
entries through the same transaction-scoped advisory lock, so a sync holding
a transaction open while our own app waits on that lock deadlocks instead of
just running slow. So the two kinds of test need different downstreams.

This stub replaces "somebody else's system," not our own decisions. Every
request still goes through the real ``OutboundScim`` (real headers, filter
escaping, status handling, error parsing), since this is an ASGI app rather
than a fake client object. It also does things our own server can't be
asked to do on command: answer 401, answer 500 for one person, or return two
accounts for one userName.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

SCIM_CONTENT_TYPE = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


def _scim_error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status, media_type=SCIM_CONTENT_TYPE)


@dataclass
class Downstream:
    """One pretend system, and the knobs a test needs to make it misbehave."""

    token: str = "downstream-token"

    accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Accounts by their remote id, which is what a real downstream would assign."""

    # ------------------------------------------------------- making it misbehave
    reject_token: bool = False
    """Answer 401 to everything. What a rotated or mistyped token looks like."""

    fail_for: set[str] = field(default_factory=set)
    """userNames this system refuses with a 500. For testing that one bad record does
    not stop the rest."""

    duplicate_for: set[str] = field(default_factory=set)
    """userNames that search returns twice, so the client refuses to guess."""

    supports_patch: bool = True

    # --------------------------------------------------------------- the record
    requests: list[tuple[str, str]] = field(default_factory=list)
    """Every (method, path) seen, so a test can assert what was and was not sent."""

    def account_for(self, user_name: str) -> dict[str, Any] | None:
        for account in self.accounts.values():
            if account.get("userName") == user_name:
                return account
        return None

    def is_active(self, user_name: str) -> bool | None:
        account = self.account_for(user_name)
        return None if account is None else bool(account.get("active", True))

    @property
    def methods(self) -> list[str]:
        return [method for method, _ in self.requests]


def build(state: Downstream) -> Starlette:
    """An ASGI app the real client can talk to."""

    def authorised(request: Request) -> bool:
        if state.reject_token:
            return False
        return request.headers.get("authorization") == f"Bearer {state.token}"

    async def service_provider_config(request: Request) -> Response:
        state.requests.append(("GET", "/ServiceProviderConfig"))
        if not authorised(request):
            return _scim_error(401, "That token is not accepted here.")
        return JSONResponse(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": state.supports_patch},
                "filter": {"supported": True, "maxResults": 200},
                "documentationUri": "https://downstream.test/docs",
            },
            media_type=SCIM_CONTENT_TYPE,
        )

    async def list_users(request: Request) -> Response:
        state.requests.append(("GET", "/Users"))
        if not authorised(request):
            return _scim_error(401, "That token is not accepted here.")

        wanted = request.query_params.get("filter", "")
        # Only the one filter shape the client sends: userName eq "value".
        user_name = ""
        if "eq" in wanted:
            user_name = wanted.split("eq", 1)[1].strip().strip('"')

        found = [
            account for account in state.accounts.values() if account.get("userName") == user_name
        ]
        if user_name in state.duplicate_for and found:
            # The same account twice, so the client has to refuse rather than guess.
            found = found * 2

        return JSONResponse(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": len(found),
                "startIndex": 1,
                "itemsPerPage": len(found),
                "Resources": found,
            },
            media_type=SCIM_CONTENT_TYPE,
        )

    async def create_user(request: Request) -> Response:
        state.requests.append(("POST", "/Users"))
        if not authorised(request):
            return _scim_error(401, "That token is not accepted here.")

        document = json.loads(await request.body())
        user_name = document.get("userName", "")

        if user_name in state.fail_for:
            return _scim_error(500, "This system is having a bad day.")

        if state.account_for(user_name) is not None:
            return _scim_error(409, f"userName {user_name!r} already exists here.", "uniqueness")

        remote_id = str(uuid.uuid4())
        stored = {**document, "id": remote_id, "active": document.get("active", True)}
        state.accounts[remote_id] = stored
        return JSONResponse(stored, status_code=201, media_type=SCIM_CONTENT_TYPE)

    async def replace_user(request: Request) -> Response:
        remote_id = request.path_params["remote_id"]
        state.requests.append(("PUT", f"/Users/{remote_id}"))
        if not authorised(request):
            return _scim_error(401, "That token is not accepted here.")

        if remote_id not in state.accounts:
            return _scim_error(404, "No such account here.")

        document = json.loads(await request.body())
        if document.get("userName") in state.fail_for:
            return _scim_error(500, "This system is having a bad day.")

        # PUT replaces, which is the point of using it for an update.
        stored = {**document, "id": remote_id}
        state.accounts[remote_id] = stored
        return JSONResponse(stored, media_type=SCIM_CONTENT_TYPE)

    async def patch_user(request: Request) -> Response:
        remote_id = request.path_params["remote_id"]
        state.requests.append(("PATCH", f"/Users/{remote_id}"))
        if not authorised(request):
            return _scim_error(401, "That token is not accepted here.")

        if not state.supports_patch:
            return _scim_error(501, "PATCH is not implemented here.")

        account = state.accounts.get(remote_id)
        if account is None:
            return _scim_error(404, "No such account here.")

        if account.get("userName") in state.fail_for:
            return _scim_error(500, "This system is having a bad day.")

        document = json.loads(await request.body())
        for operation in document.get("Operations", []):
            if operation.get("path") == "active":
                # Only `active` changes, which is what makes this the safe way to
                # deactivate: nothing else about the record is touched.
                account["active"] = bool(operation.get("value"))

        return JSONResponse(account, media_type=SCIM_CONTENT_TYPE)

    return Starlette(
        routes=[
            Route("/scim/v2/ServiceProviderConfig", service_provider_config),
            Route("/scim/v2/Users", list_users, methods=["GET"]),
            Route("/scim/v2/Users", create_user, methods=["POST"]),
            Route("/scim/v2/Users/{remote_id}", replace_user, methods=["PUT"]),
            Route("/scim/v2/Users/{remote_id}", patch_user, methods=["PATCH"]),
        ]
    )
