"""Sending SCIM back, with the right content type and the right envelope.

Every SCIM handler goes through here so the media type and the list envelope
can't drift apart between endpoints - the kind of bug that only shows up
against the one provider that actually checks.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from iam.schemas.scim import ListResponse
from iam.scim.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, SCIM_MEDIA_TYPE
from iam.scim.errors import ScimError


def scim_json(document: dict[str, Any], status_code: int = status.HTTP_200_OK) -> JSONResponse:
    """One SCIM document, as application/scim+json.

    Not application/json. Some providers check the content type and ignore a
    response that claims to be plain JSON - which looks from our side like a
    sync that ran fine and did nothing.
    """
    return JSONResponse(content=document, status_code=status_code, media_type=SCIM_MEDIA_TYPE)


def resource_json(resource: BaseModel, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    """A single resource.

    `exclude_none` since SCIM wants a field absent rather than null, and
    `by_alias` since the wire uses camelCase while our code uses Python names.
    """
    return scim_json(
        resource.model_dump(mode="json", by_alias=True, exclude_none=True),
        status_code=status_code,
    )


def list_json(resources: Sequence[BaseModel], *, total: int, start_index: int) -> JSONResponse:
    """A page of resources in SCIM's list envelope.

    `itemsPerPage` is how many are actually in this response, not how many
    were requested - a provider that reads the requested size instead keeps
    paging past the end of the results.
    """
    items = [
        resource.model_dump(mode="json", by_alias=True, exclude_none=True) for resource in resources
    ]
    envelope = ListResponse(
        total_results=total,
        start_index=start_index,
        items_per_page=len(items),
        resources=items,
    )
    return scim_json(envelope.model_dump(mode="json", by_alias=True, exclude_none=True))


def paging(start_index: int | None, count: int | None) -> tuple[int, int]:
    """Turn SCIM's 1-based paging into the offset and limit a query wants.

    startIndex is 1-based, and the spec treats a value below 1 as 1 rather
    than rejecting it. Getting the off-by-one wrong here either skips the
    first person in the directory or loops forever on the same page.
    """
    index = max(1, start_index or 1)
    size = DEFAULT_PAGE_SIZE if count is None else max(0, min(count, MAX_PAGE_SIZE))
    return index - 1, size


async def scim_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Answer a ScimError with SCIM's error document.

    Registered in main.py so no handler builds the envelope itself. Takes a
    bare Exception because that's what Starlette's handler protocol requires;
    the isinstance check also keeps mypy happy.
    """
    if not isinstance(exc, ScimError):  # pragma: no cover - registered for ScimError only
        raise exc
    return scim_json(exc.as_document(), status_code=exc.status_code)
