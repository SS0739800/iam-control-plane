"""The three documents a provider reads before it sends anything.

ServiceProviderConfig says what this server can do. ResourceTypes says what
kinds of thing live here. Schemas says what attributes those have.

These need to be accurate: a provider plans its sync around the answers.
Claim `patch: false` and it uses PUT for everything; claim `filter:
supported` and it sends filters expecting them to work. So `filter` says
supported (true for the subset in filters.py), and `sort`, `etag`, and
`bulk` all say false, because they are.

These are readable with a valid token but describe nothing about anybody, so
this is the one part of the SCIM surface where being wrong is just
embarrassing, not dangerous.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from iam.deps import SettingsDep
from iam.scim.auth import ScimClientDep
from iam.scim.constants import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_RESOURCE,
    GROUP_SCHEMA,
    MAX_PAGE_SIZE,
    RESOURCE_TYPE_SCHEMA,
    SCIM_PREFIX,
    SERVICE_PROVIDER_CONFIG_SCHEMA,
    USER_RESOURCE,
    USER_SCHEMA,
)
from iam.scim.responses import scim_json

router = APIRouter(prefix=SCIM_PREFIX, tags=["scim"])


@router.get("/ServiceProviderConfig", summary="What this server supports")
async def service_provider_config(settings: SettingsDep, client: ScimClientDep) -> Response:
    """What we can do, answered honestly.

    `patch` is true - this is how deprovisioning arrives. A provider told
    patch is unsupported falls back to PUT, sending a whole resource to
    change one boolean.

    `bulk` is false. A provider that thinks otherwise would post a bundle of
    operations to an endpoint that doesn't exist.
    """
    root = settings.base_url.rstrip("/")
    return scim_json(
        {
            "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
            "documentationUri": f"{root}/api/docs",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_PAGE_SIZE},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": (
                        "A bearer token issued by this console. Send it as "
                        "Authorization: Bearer <token>."
                    ),
                    "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                    "primary": True,
                }
            ],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": f"{root}{SCIM_PREFIX}/ServiceProviderConfig",
            },
        }
    )


def _resource_type(name: str, schema: str, extensions: list[str], root: str) -> dict[str, object]:
    return {
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": name,
        "name": name,
        "endpoint": f"/{name}s",
        "description": f"{name} resources",
        "schema": schema,
        "schemaExtensions": [{"schema": extension, "required": False} for extension in extensions],
        "meta": {
            "resourceType": "ResourceType",
            "location": f"{root}{SCIM_PREFIX}/ResourceTypes/{name}",
        },
    }


@router.get("/ResourceTypes", summary="The kinds of thing that live here")
async def resource_types(settings: SettingsDep, client: ScimClientDep) -> Response:
    root = settings.base_url.rstrip("/")
    types = [
        _resource_type(USER_RESOURCE, USER_SCHEMA, [ENTERPRISE_USER_SCHEMA], root),
        _resource_type(GROUP_RESOURCE, GROUP_SCHEMA, [], root),
    ]
    return scim_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(types),
            "startIndex": 1,
            "itemsPerPage": len(types),
            "Resources": types,
        }
    )


def _attribute(
    name: str,
    *,
    kind: str = "string",
    required: bool = False,
    multi: bool = False,
    mutability: str = "readWrite",
    unique: str = "none",
    sub: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    attribute: dict[str, object] = {
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": False,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": unique,
    }
    if sub:
        attribute["subAttributes"] = sub
    return attribute


USER_ATTRIBUTES = [
    _attribute("userName", required=True, unique="server"),
    _attribute("externalId", unique="server"),
    _attribute("displayName"),
    _attribute(
        "name",
        kind="complex",
        sub=[_attribute("givenName"), _attribute("familyName"), _attribute("formatted")],
    ),
    _attribute(
        "emails",
        kind="complex",
        multi=True,
        sub=[_attribute("value"), _attribute("type"), _attribute("primary", kind="boolean")],
    ),
    _attribute("active", kind="boolean"),
    # Read-only: tells a provider that membership is written on the group,
    # not here.
    _attribute("groups", kind="complex", multi=True, mutability="readOnly"),
]

GROUP_ATTRIBUTES = [
    _attribute("displayName", required=True, unique="server"),
    _attribute("externalId", unique="server"),
    _attribute(
        "members",
        kind="complex",
        multi=True,
        sub=[_attribute("value"), _attribute("display")],
    ),
]

ENTERPRISE_ATTRIBUTES = [
    _attribute("employeeNumber"),
    _attribute("department"),
    _attribute("manager", kind="complex", sub=[_attribute("value"), _attribute("displayName")]),
]


def _schema(
    urn: str, name: str, description: str, attributes: list[dict[str, object]], root: str
) -> dict[str, object]:
    return {
        "id": urn,
        "name": name,
        "description": description,
        "attributes": attributes,
        "meta": {"resourceType": "Schema", "location": f"{root}{SCIM_PREFIX}/Schemas/{urn}"},
    }


@router.get("/Schemas", summary="The attributes each kind of thing has")
async def schemas(settings: SettingsDep, client: ScimClientDep) -> Response:
    root = settings.base_url.rstrip("/")
    documents = [
        _schema(USER_SCHEMA, "User", "A person in the directory", USER_ATTRIBUTES, root),
        _schema(GROUP_SCHEMA, "Group", "A group of people", GROUP_ATTRIBUTES, root),
        _schema(
            ENTERPRISE_USER_SCHEMA,
            "EnterpriseUser",
            "The employment details an HRMS cares about",
            ENTERPRISE_ATTRIBUTES,
            root,
        ),
    ]
    return scim_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(documents),
            "startIndex": 1,
            "itemsPerPage": len(documents),
            "Resources": documents,
        }
    )
