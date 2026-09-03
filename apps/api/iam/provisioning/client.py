"""Speaking SCIM to somebody else's system.

This is the mirror of iam/routers/scim_users.py, which is our server side.

A few rules this client follows:
- Removing somebody sends `active: false`, never DELETE. Same as our own
  server: a deactivated account keeps its history, and a rehire can revive it
  instead of creating a duplicate.
- "Worked" means a 2xx, not just "no exception". A 401 is a successful HTTP
  request that provisioned nothing, so every response status is checked.
- Redirects are not followed (ADR 0007) - a 302 is treated as a failure.
- This module makes one request and reports what happened. Retries are the
  sync's job, since it knows how many attempts a link has already had.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

SCIM_CONTENT_TYPE = "application/scim+json"

REQUEST_TIMEOUT = 15.0
"""Seconds to wait on a downstream.

Longer than the mail timeout since a timed-out push leaves a link that someone
has to resolve. Still short enough that one unresponsive target can't hold up
a whole sync.
"""

MAX_ERROR_BODY = 500
"""How much of a downstream's error to keep.

Enough for a SCIM error document. Caps it so an HTML error page doesn't dump
a stack trace into our audit log.
"""


class PushFailed(Exception):
    """One request to a downstream did not work.

    Carries the status when there was one. `status` being None means the
    request never got an answer at all (connection refused, timeout, DNS) -
    a different problem than a rejected request, usually for a different
    person to fix.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def is_authentication(self) -> bool:
        """Whether the token is the problem.

        Every push to this target will fail the same way until someone
        re-enters it, so a sync should stop here instead of retrying the same
        401 for every person.
        """
        return self.status in (401, 403)

    @property
    def is_conflict(self) -> bool:
        """Something with this userName is already there.

        Not a retryable failure and not fatal either. The account exists, we
        just don't know its id yet, so the fix is to look it up and adopt it.
        This is what onboarding a downstream that already has people looks
        like.
        """
        return self.status == 409

    @property
    def is_missing(self) -> bool:
        """The account we tried to update is not there.

        Recoverable: it means we should create instead of update, which is
        what a link with a stale remote_id needs.
        """
        return self.status == 404


@dataclass(frozen=True, slots=True)
class RemoteAccount:
    """What a downstream told us about an account."""

    remote_id: str
    user_name: str
    active: bool
    raw: dict[str, Any] = field(default_factory=dict)


def user_payload(
    *,
    user_name: str,
    email: str,
    display_name: str,
    given_name: str | None = None,
    family_name: str | None = None,
    department: str | None = None,
    external_id: str | None = None,
    active: bool = True,
) -> dict[str, Any]:
    """Build the SCIM document for one person.

    Only includes attributes a downstream can actually use - extra fields
    risk rejection by a stricter schema, and a rejected create leaves someone
    with no account.

    externalId is our own id, so a downstream can match its account back to
    us. Our server side uses the same field for the same reason.
    """
    document: dict[str, Any] = {
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "displayName": display_name,
        "active": active,
        "emails": [{"value": email, "type": "work", "primary": True}],
    }

    if external_id:
        document["externalId"] = external_id

    if given_name or family_name:
        document["name"] = {
            key: value
            for key, value in (("givenName", given_name), ("familyName", family_name))
            if value
        }

    if department:
        document["schemas"] = [USER_SCHEMA, ENTERPRISE_SCHEMA]
        document[ENTERPRISE_SCHEMA] = {"department": department}

    return document


def deactivate_patch() -> dict[str, Any]:
    """Deactivate a user via PATCH.

    Not PUT: PUT means "this is the whole resource" and would blank every
    attribute the downstream holds that we don't send. A leaver should lose
    access, not their whole record.
    """
    return {
        "schemas": [PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    }


def reactivate_patch() -> dict[str, Any]:
    """Bring a deprovisioned account back, for a rehire."""
    return {
        "schemas": [PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": True}],
    }


class OutboundScim:
    """One downstream, and the requests we make to it.

    Takes the decrypted token rather than the target row, so nothing here can
    accidentally log a whole model with a secret in it, and tests don't need
    a database.
    """

    def __init__(self, *, base_url: str, token: str, client: httpx.AsyncClient | None = None):
        self._root = base_url.rstrip("/")
        self._token = token
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": SCIM_CONTENT_TYPE,
            "Accept": SCIM_CONTENT_TYPE,
        }

    async def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> httpx.Response:
        """Make one request and insist on a 2xx.

        Raises:
            PushFailed: Anything other than success, including a request that never
                got an answer.
        """
        url = f"{self._root}{path}"
        owned = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            # No redirects, per ADR 0007 - following one would move the
            # destination away from the address somebody reviewed.
            follow_redirects=False,
        )

        try:
            response = await client.request(method, url, headers=self._headers, json=json)
        except httpx.HTTPError as exc:
            # No status here since there was no answer - usually the network
            # or the target being down, not something about the request.
            raise PushFailed(f"could not reach {url}: {exc}") from exc
        finally:
            if owned:
                await client.aclose()

        if response.is_success:
            return response

        body = response.text[:MAX_ERROR_BODY].strip()
        raise PushFailed(
            f"{method} {path} answered {response.status_code}" + (f": {body}" if body else ""),
            status=response.status_code,
        )

    async def find_user(self, user_name: str) -> RemoteAccount | None:
        """Look for an account by userName.

        Used when adopting a downstream that already has accounts, so a first
        sync links to what's there instead of creating duplicates. Not used
        on the normal path - that's what the links table is for.

        The filter value is escaped per SCIM rules, since a userName
        containing a quote would otherwise change the filter's meaning.
        """
        escaped = user_name.replace("\\", "\\\\").replace('"', '\\"')
        response = await self._request("GET", f'/Users?filter=userName eq "{escaped}"')

        document = response.json()
        resources = document.get("Resources") or []
        if not resources:
            return None

        if len(resources) > 1:
            # Ambiguous - refuse instead of guessing. Picking wrong here would
            # link us to the wrong account with no way to notice later.
            raise PushFailed(
                f"{len(resources)} accounts downstream have userName {user_name!r}. "
                "Refusing to guess which one is theirs."
            )

        found = resources[0]
        return RemoteAccount(
            remote_id=str(found.get("id")),
            user_name=str(found.get("userName", user_name)),
            active=bool(found.get("active", True)),
            raw=found,
        )

    async def create_user(self, payload: dict[str, Any]) -> RemoteAccount:
        """Create an account and keep the id it was given."""
        response = await self._request("POST", "/Users", json=payload)
        document = response.json()

        remote_id = document.get("id")
        if not remote_id:
            # Without an id we can never update or deactivate this account.
            # Fail now instead of discovering it during someone's leaver process.
            raise PushFailed(
                "the account was created but the response carried no id, so there "
                "would be no way to update or deactivate it later",
                status=response.status_code,
            )

        return RemoteAccount(
            remote_id=str(remote_id),
            user_name=str(document.get("userName", payload.get("userName", ""))),
            active=bool(document.get("active", True)),
            raw=document,
        )

    async def replace_user(self, remote_id: str, payload: dict[str, Any]) -> RemoteAccount:
        """Update an account to match what we hold.

        Uses PUT, not PATCH - the opposite choice from deactivation. Our
        directory is the source of truth for these fields, so we send the
        whole resource; a PATCH would leave stale values for any attribute
        we stopped sending.
        """
        response = await self._request("PUT", f"/Users/{remote_id}", json=payload)
        document = response.json()
        return RemoteAccount(
            remote_id=str(document.get("id", remote_id)),
            user_name=str(document.get("userName", "")),
            active=bool(document.get("active", True)),
            raw=document,
        )

    async def set_active(self, remote_id: str, *, active: bool) -> None:
        """Deactivate or reactivate one account.

        Uses PATCH, not PUT, so nothing else about their record is touched.
        See deactivate_patch.
        """
        patch = reactivate_patch() if active else deactivate_patch()
        await self._request("PATCH", f"/Users/{remote_id}", json=patch)

        logger.info(
            "provisioning.set_active",
            extra={"remote_id": remote_id, "active": active, "target": self._root},
        )

    async def probe(self) -> str:
        """Check the target answers and the token works, without changing anything.

        Reads ServiceProviderConfig, which every SCIM server publishes and
        which describes nothing about anybody. Good to call when someone
        registers a target, to confirm the address and token work before
        anyone depends on them.
        """
        response = await self._request("GET", "/ServiceProviderConfig")
        document = response.json()

        supports_patch = bool((document.get("patch") or {}).get("supported"))
        if not supports_patch:
            # Log this now rather than discovering it during a leaver process.
            # Without PATCH, deactivating means PUT, which blanks anything we
            # don't send.
            logger.warning(
                "provisioning.no_patch_support",
                extra={
                    "target": self._root,
                    "detail": (
                        "This downstream says it does not support PATCH, so "
                        "deactivating somebody would have to replace their whole "
                        "record."
                    ),
                },
            )

        return str(document.get("documentationUri") or self._root)
