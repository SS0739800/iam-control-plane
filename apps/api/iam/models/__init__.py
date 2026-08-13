"""The database tables.

Every model file has to be imported here. Alembic looks at Base.metadata to work
out what migrations to write, and a table it never imported is simply invisible —
you get an empty migration instead of an error, which is worse.

It also means SQLAlchemy sorts out the relationships that refer to each other by
name ("Group", "AppAssignment") on import rather than on the first query.
"""

from __future__ import annotations

from iam.models.application import AppAssignment, Application
from iam.models.audit import GENESIS_HASH, HASH_LENGTH, AuditEvent
from iam.models.base import Base
from iam.models.enums import (
    ActorType,
    AppProtocol,
    AppStatus,
    AuditOutcome,
    IdentitySource,
    PlatformRole,
    PrincipalType,
)
from iam.models.group import Group, GroupMember
from iam.models.user import User

__all__ = [
    "GENESIS_HASH",
    "HASH_LENGTH",
    "ActorType",
    "AppAssignment",
    "AppProtocol",
    "AppStatus",
    "Application",
    "AuditEvent",
    "AuditOutcome",
    "Base",
    "Group",
    "GroupMember",
    "IdentitySource",
    "PlatformRole",
    "PrincipalType",
    "User",
]
