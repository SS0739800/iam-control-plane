"""Speaking SCIM to somebody else's system.

The mirror of iam/routers/scim_users.py, which is the server side. Writing both ends
of the same protocol has one useful consequence: every awkward thing the server side
had to tolerate is a thing this side must avoid doing.

Deactivating, never deleting
----------------------------

Removing somebody sends ``active: false``. It never sends DELETE, even though the
protocol has one and some downstreams implement it.

That is the same decision our own server made, from the other side. A deactivated
account keeps its history — who they were, what they had, when it stopped — and a
deleted one takes that with it. It also means a rehire revives an account instead of
creating a second one that looks identical and shares none of the past.

What "it worked" means
----------------------

Only a 2xx. Not "no exception raised", which is the mistake this kind of client
usually makes: a 401 is a perfectly successful HTTP request that provisioned nothing.
So every response is checked, and the failure carries the status and the body,
because a downstream's own error message is almost always the fastest way to the
cause.

Redirects are not followed, per ADR 0007. A target that answers 302 is a failure
rather than a second request to wherever it pointed.

No retries in here
------------------

This makes one request and reports what happened. Deciding whether to try again is
the sync's business, because it is the thing that knows how many attempts a link has
already had and whether an account exists out there — and a retry loop buried in a
transport function is a retry loop nobody can see or stop.
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

Longer than the mail timeout because this one matters — a push that times out leaves
a link in a state somebody has to resolve — and short enough that one unresponsive
target cannot hold a sync open indefinitely.
"""

MAX_ERROR_BODY = 500
"""How much of a downstream's error to keep.

Enough for a SCIM error document, which is small. A downstream that answers with an
HTML error page should not put a stack trace in our audit log.
"""


class PushFailed(Exception):
    """One request to a downstream did not work.

    Carries the status when there was one. ``status`` being None means the request
    never got an answer — a connection refused, a timeout, DNS — which is a different
    problem from a rejected one and usually a different person's to fix.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def is_authentication(self) -> bool:
        """Whether the token is the problem.

        Worth telling apart: every push to this target will fail the same way until
        somebody re-enters it, so a sync should stop rather than work through a
        thousand people collecting the same 401.
        """
        return self.status in (401, 403)

    @property
    def is_missing(self) -> bool:
        """The account we tried to update is not there.

        Recoverable, and specifically: it means creating rather than updating, which
        is what a link with a stale remote_id needs.
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

    Only the attributes a downstream can actually use. Every extra field is one more
    thing to keep true and one more thing that can be rejected by a system with a
    stricter schema — and a rejected create is a person with no account.

    externalId is our own id, which is what lets a downstream match its account back
    to us. It is the field our own server side leans on for exactly the same reason.
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
    """The one operation that matters most in this whole phase.

    PATCH rather than PUT, because PUT means "this is the whole resource" and would
    blank every attribute the downstream holds that we do not send. A leaver should
    lose their access, not their record.
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
    accidentally log a whole model with a secret in it, and so a test needs no
    database.
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
            # Per ADR 0007. Following one would move the destination away from the
            # address somebody reviewed.
            follow_redirects=False,
        )

        try:
            response = await client.request(method, url, headers=self._headers, json=json)
        except httpx.HTTPError as exc:
            # No status, because there was no answer. The distinction matters: this is
            # usually the network or the target being down rather than anything about
            # the request.
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

        Used when adopting a downstream that already has accounts, so a first sync
        links to what is there instead of creating a second copy of everybody. Not
        used on the normal path — that is what the links table is for.

        The filter value is quoted with the SCIM escaping rules: a userName containing
        a quote would otherwise change the filter's meaning, which on somebody else's
        server is their injection bug and our fault.
        """
        escaped = user_name.replace("\\", "\\\\").replace('"', '\\"')
        response = await self._request("GET", f'/Users?filter=userName eq "{escaped}"')

        document = response.json()
        resources = document.get("Resources") or []
        if not resources:
            return None

        if len(resources) > 1:
            # Ambiguous, so refused rather than guessed. Picking one would link us to
            # an account at random and the wrong choice is invisible afterwards.
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
            # A downstream that creates an account and does not say what its id is has
            # left us unable to ever update or deactivate it. Better to fail loudly
            # now than to discover it during somebody's leaver process.
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

        PUT here rather than PATCH, deliberately, and it is the opposite choice from
        deactivation. This is the path that says "our directory is the truth for these
        fields", so sending the whole resource is the point — a PATCH would leave a
        stale value in place whenever we stopped sending an attribute.
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

        The leaver path, and PATCH rather than PUT so nothing else about their record
        is touched — see deactivate_patch.
        """
        patch = reactivate_patch() if active else deactivate_patch()
        await self._request("PATCH", f"/Users/{remote_id}", json=patch)

        logger.info(
            "provisioning.set_active",
            extra={"remote_id": remote_id, "active": active, "target": self._root},
        )

    async def probe(self) -> str:
        """Check the target answers and the token works, without changing anything.

        Reads ServiceProviderConfig, which every SCIM server publishes and which
        describes nothing about anybody. That makes it the right thing to call when
        somebody registers a target: it proves the address and the token before the
        first person depends on them.
        """
        response = await self._request("GET", "/ServiceProviderConfig")
        document = response.json()

        supports_patch = bool((document.get("patch") or {}).get("supported"))
        if not supports_patch:
            # Worth saying out loud rather than discovering during a leaver process.
            # Without PATCH, deactivating means PUT, which blanks anything we do not
            # send.
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
