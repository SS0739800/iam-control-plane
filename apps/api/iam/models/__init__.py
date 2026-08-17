"""The database tables.

Every model file has to be imported here. Alembic looks at Base.metadata to work
out what migrations to write, and a table it never imported is simply invisible —
you get an empty migration instead of an error, which is worse.

It also means SQLAlchemy sorts out the relationships that refer to each other by
name ("Group", "AppAssignment") on import rather than on the first query.
"""

from __future__ import annotations

from iam.models.access import RevokedGrantReason, RoleGrant
from iam.models.application import AppAssignment, Application
from iam.models.audit import GENESIS_HASH, HASH_LENGTH, AuditEvent
from iam.models.base import Base
from iam.models.enums import (
    ActorType,
    AppProtocol,
    AppStatus,
    AuditOutcome,
    GrantSource,
    IdentitySource,
    PlatformRole,
    PrincipalType,
)
from iam.models.group import Group, GroupMember
from iam.models.rules import ATTRIBUTES, AccessRule
from iam.models.saml import (
    IdentityProvider,
    SamlAssertionSeen,
    SamlRequestState,
    SamlSession,
)
from iam.models.scim import ScimClient
from iam.models.user import User

__all__ = [
    "ATTRIBUTES",
    "GENESIS_HASH",
    "HASH_LENGTH",
    "AccessRule",
    "ActorType",
    "AppAssignment",
    "AppProtocol",
    "AppStatus",
    "Application",
    "AuditEvent",
    "AuditOutcome",
    "Base",
    "GrantSource",
    "Group",
    "GroupMember",
    "IdentityProvider",
    "IdentitySource",
    "MembershipSource",
    "PlatformRole",
    "PrincipalType",
    "RevokedGrantReason",
    "RoleGrant",
    "RuleOperator",
    "SamlAssertionSeen",
    "SamlRequestState",
    "SamlSession",
    "ScimClient",
    "User",
]
