"""SCIM's error shape, which is not FastAPI's.

FastAPI answers errors with ``{"detail": "..."}``. SCIM expects a document with
its own schema URN, the status as a *string*, and an optional ``scimType`` that
says which kind of wrong this is. A provider reads scimType to decide what to do
next — ``uniqueness`` means "it already exists, go and update it instead", while
a bare 400 means "give up and log something".

So getting this shape right is not pedantry about the spec. It is the difference
between a provider recovering from a conflict and a provider stopping.
"""

from __future__ import annotations

from typing import Any

from fastapi import status

from iam.scim.constants import ERROR_SCHEMA


class ScimType:
    """The values RFC 7644 allows in scimType, and what each one tells a client."""

    INVALID_FILTER = "invalidFilter"
    """The filter was malformed, or asked for something we don't support."""

    TOO_MANY = "tooMany"
    """The filter matched more than we're willing to return."""

    UNIQUENESS = "uniqueness"
    """Something with that userName or externalId already exists. The useful one:
    a provider seeing this knows to PATCH rather than POST."""

    MUTABILITY = "mutability"
    """They tried to change something that can't be changed after creation."""

    INVALID_SYNTAX = "invalidSyntax"
    """The body wasn't a valid SCIM document."""

    INVALID_PATH = "invalidPath"
    """A PATCH path we couldn't parse or don't support."""

    NO_TARGET = "noTarget"
    """A PATCH path that parsed but matched nothing to change."""

    INVALID_VALUE = "invalidValue"
    """A value was the wrong type, or missing when it's required."""

    INVALID_VERS = "invalidVers"
    MUTABILITY_READ_ONLY = "mutability"


class ScimError(Exception):
    """An error to answer a SCIM request with.

    Raised anywhere in a SCIM handler and turned into the right document by the
    exception handler registered in main.py. Doing it that way means individual
    handlers never build the envelope themselves, so the shape can't drift
    between endpoints.
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        scim_type: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type

    def as_document(self) -> dict[str, Any]:
        """The body to send back.

        ``status`` is a string, not a number. That is what the spec says, and
        providers do reject the numeric form.
        """
        document: dict[str, Any] = {
            "schemas": [ERROR_SCHEMA],
            "status": str(self.status_code),
            "detail": self.detail,
        }
        if self.scim_type:
            document["scimType"] = self.scim_type
        return document


def not_found(resource: str, resource_id: str) -> ScimError:
    return ScimError(
        status.HTTP_404_NOT_FOUND,
        f"{resource} {resource_id} does not exist.",
    )


def already_exists(field: str, value: str) -> ScimError:
    """409 with scimType uniqueness — the one a provider can act on.

    A provider that gets this knows the record is already here and switches to
    updating it. Answering a plain 400 instead is how you end up with a sync that
    reports failure forever over somebody who exists perfectly well.
    """
    return ScimError(
        status.HTTP_409_CONFLICT,
        f"A record with {field} {value!r} already exists.",
        scim_type=ScimType.UNIQUENESS,
    )


def bad_filter(detail: str) -> ScimError:
    return ScimError(
        status.HTTP_400_BAD_REQUEST,
        detail,
        scim_type=ScimType.INVALID_FILTER,
    )


def bad_value(detail: str) -> ScimError:
    return ScimError(
        status.HTTP_400_BAD_REQUEST,
        detail,
        scim_type=ScimType.INVALID_VALUE,
    )


def bad_path(detail: str) -> ScimError:
    return ScimError(
        status.HTTP_400_BAD_REQUEST,
        detail,
        scim_type=ScimType.INVALID_PATH,
    )
