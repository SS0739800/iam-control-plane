"""The strings SCIM fixes, gathered so they're spelled once.

Every one of these is compared exactly by the provider on the other end. A typo
in a URN doesn't fail loudly — it produces a resource the provider decides it
doesn't understand, and the symptom is a sync that silently does nothing.
"""

from __future__ import annotations

SCIM_MEDIA_TYPE = "application/scim+json"
"""What SCIM responses are, per RFC 7644.

Not application/json. Some providers check, and the ones that don't are not a
reason to be wrong.
"""

# ------------------------------------------------------------------- schemas

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
"""The extension carrying employeeNumber, department and manager.

Those are core to an HRMS and deliberately not in the base User schema, so a
provider that wants to send them has to say so with this URN.
"""

LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"

# ------------------------------------------------------------- resource types

USER_RESOURCE = "User"
GROUP_RESOURCE = "Group"

# -------------------------------------------------------------------- paths

SCIM_PREFIX = "/scim/v2"
"""Where our SCIM surface lives.

Outside /api, next to /saml, because a provider posts here directly and this is
part of the site rather than part of the console's own JSON API. Caddy proxies
/scim/* on its own rule. See docs/adr/0003-single-origin.md.
"""

# --------------------------------------------------------------- pagination

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
"""SCIM pages are 1-based and counted in startIndex/count, not offset/limit.

Kept generous because a provider syncing a directory wants big pages, and every
page is another round trip during a full sync.
"""
