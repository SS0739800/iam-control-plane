"""HTTP surfaces.

Mounted by :func:`iam.main.create_app`. Prefixes are assigned there, not here,
so the route table is readable in one place — which matters because Caddy's
single-origin config has to mirror it exactly.

    health   /api/health, /api/health/ready        P0
    saml     /saml/metadata, /saml/acs, /saml/sls  P2
    scim     /scim/v2/Users, /scim/v2/Groups       P3
    admin    /api/users, /api/groups, /api/apps    P1
    idp      /idp/metadata, /idp/sso, /idp/slo     P5
"""

from __future__ import annotations
