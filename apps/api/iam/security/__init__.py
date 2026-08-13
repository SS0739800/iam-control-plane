"""Who's calling and what they're allowed to do.

- permissions.py — the list of permissions and which role gets which
- actor.py — working out who's calling (a stand-in until P2 adds real login)
- guards.py — the require(...) check you put on a route
"""

from __future__ import annotations

from iam.security.actor import DEV_ACTOR_HEADER, Actor, CurrentActor, resolve_actor
from iam.security.guards import require
from iam.security.permissions import ROLE_PERMISSIONS, Permission, permissions_for

__all__ = [
    "DEV_ACTOR_HEADER",
    "ROLE_PERMISSIONS",
    "Actor",
    "CurrentActor",
    "Permission",
    "permissions_for",
    "require",
    "resolve_actor",
]
