"""Who has been given what, and why.

- roles.py — console role grants, and the cached copy on the user row
- lifecycle.py — someone left, take everything away
- rules.py — groups granted from somebody's attributes (joiner and mover)

Coming in the rest of P4: the review screens that read it all back, and access
requests with an approval step.
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
from iam.access.rules import (
    Reconciliation,
    RuleRefused,
    affected_by,
    matches,
    matching_rules,
    reconcile,
    reconcile_group,
    validate,
)

__all__ = [
    "Drift",
    "Granter",
    "Reconciliation",
    "RemovedAccess",
    "RoleGrantRefused",
    "RuleRefused",
    "affected_by",
    "cut_access",
    "effective_role",
    "expire_due_grants",
    "expire_due_grants_for",
    "find_drift",
    "grant_role",
    "history",
    "live_grant",
    "matches",
    "matching_rules",
    "reconcile",
    "reconcile_group",
    "revoke_for_leaver",
    "revoke_role",
    "validate",
]
