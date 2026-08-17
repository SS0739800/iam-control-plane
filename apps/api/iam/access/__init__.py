"""Who has been given what, and why.

- roles.py — console role grants, and the cached copy on the user row
- lifecycle.py — someone left, take everything away

Coming in the rest of P4: access rules that grant by attribute, and the review
screens that read it all back.
"""

from __future__ import annotations

from iam.access.lifecycle import RemovedAccess, cut_access
from iam.access.roles import (
    Drift,
    Granter,
    RoleGrantRefused,
    effective_role,
    expire_due_grants,
    expire_due_grants_for,
    find_drift,
    grant_role,
    history,
    live_grant,
    revoke_for_leaver,
    revoke_role,
)

__all__ = [
    "Drift",
    "Granter",
    "RemovedAccess",
    "RoleGrantRefused",
    "cut_access",
    "effective_role",
    "expire_due_grants",
    "expire_due_grants_for",
    "find_drift",
    "grant_role",
    "history",
    "live_grant",
    "revoke_for_leaver",
    "revoke_role",
]
