"""What each role is allowed to do.

Routes check permissions, never roles. So a handler says "I need users:read", not
"the caller must be an admin". If we ever add a fifth role, we edit the table
below and nothing else. Check roles directly and you end up hunting for
`if role == ADMIN` in every file instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from iam.models.enums import PlatformRole


class Permission(StrEnum):
    """One thing someone can do. Reading and changing are always separate."""

    USERS_READ = "users:read"
    USERS_WRITE = "users:write"

    GROUPS_READ = "groups:read"
    GROUPS_WRITE = "groups:write"

    APPS_READ = "apps:read"
    APPS_WRITE = "apps:write"

    IDP_READ = "idp:read"
    IDP_WRITE = "idp:write"
    """Configure which outside systems we believe about identity. Admin only.

    Covers both halves of that: registering an identity provider, and issuing or
    revoking the tokens that let a system provision people into the directory.
    They are the same decision asked twice — one at the moment somebody logs in,
    the other continuously — and both reduce to "whoever controls this can decide
    who exists here".

    Helpdesk and auditor can look, so they can answer "is SSO configured" and "is
    the sync running". Neither can change it."""

    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    """Run the tamper check on the audit log. Kept separate from just reading it,
    because it's the auditor's job rather than everyday lookup."""


# Spelled out because mypy reads `frozenset(Permission)` as frozenset[str], which
# then doesn't match the table below.
_ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)

ROLE_PERMISSIONS: Mapping[PlatformRole, frozenset[Permission]] = {
    PlatformRole.ADMIN: _ALL_PERMISSIONS,
    # Helpdesk fixes access problems. They can look anything up and edit a user,
    # but not change groups or apps. Editing one user affects one person; changing
    # a group changes access for everyone in it.
    PlatformRole.HELPDESK: frozenset(
        {
            Permission.USERS_READ,
            Permission.USERS_WRITE,
            Permission.GROUPS_READ,
            Permission.APPS_READ,
            Permission.IDP_READ,
            Permission.AUDIT_READ,
        }
    ),
    # Can see everything, change nothing, and run the tamper check. The person who
    # reviews access shouldn't also be able to grant it.
    PlatformRole.AUDITOR: frozenset(
        {
            Permission.USERS_READ,
            Permission.GROUPS_READ,
            Permission.APPS_READ,
            Permission.IDP_READ,
            Permission.AUDIT_READ,
            Permission.AUDIT_VERIFY,
        }
    ),
    # Nothing. Regular staff use the HRMS, not this console. An empty set says
    # that more clearly than inventing self-service permissions we haven't built.
    PlatformRole.EMPLOYEE: frozenset(),
}


def permissions_for(role: PlatformRole) -> frozenset[Permission]:
    """What a role can do. A role we don't recognise gets nothing."""
    return ROLE_PERMISSIONS.get(role, frozenset())
