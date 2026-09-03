"""The database tables.

Every model file must be imported here so Alembic sees it in Base.metadata.
A table that isn't imported won't show up in migrations, and you won't get
an error for it either.
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
from iam.models.idp_session import IdpSession
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from iam.models.requests import AccessRequest
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
    "AccessRequest",
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
    "IdpSession",
    "LinkState",
    "MembershipSource",
    "PlatformRole",
    "PrincipalType",
    "ProvisioningLink",
    "ProvisioningTarget",
    "RequestState",
    "RevokedGrantReason",
    "RoleGrant",
    "RuleOperator",
    "SamlAssertionSeen",
    "SamlRequestState",
    "SamlSession",
    "ScimClient",
    "User",
]
