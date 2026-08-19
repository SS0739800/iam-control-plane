"""The HTTP endpoints.

main.py is what attaches these to the app and sets their URL prefixes, so you can
read the whole route list in one place. That matters because the Caddyfile has to
match it.

    health   /api/health, /api/health/ready        P0
    saml     /saml/metadata, /saml/acs, /saml/sls  P2
    scim     /scim/v2/Users, /scim/v2/Groups       P3
    admin    /api/users, /api/groups, /api/apps    P1
    idp      /idp/metadata, /idp/sso, /idp/slo     P5
"""

from __future__ import annotations
