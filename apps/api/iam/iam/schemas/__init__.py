"""The shapes the API sends and accepts.

Separate from iam.models on purpose. Those describe the database; these describe
what goes over the wire. If they were the same thing, renaming a column would
break every client, and adding a column would quietly start publishing it.
"""

from __future__ import annotations

from iam.schemas.audit import AuditEventOut, ChainVerification
from iam.schemas.common import AppRef, DashboardCounts, GroupRef, UserRef
from iam.schemas.directory import (
    ApplicationDetail,
    ApplicationSummary,
    GroupDetail,
    GroupSummary,
    UserDetail,
    UserSummary,
    UserUpdate,
)

__all__ = [
    "AppRef",
    "ApplicationDetail",
    "ApplicationSummary",
    "AuditEventOut",
    "ChainVerification",
    "DashboardCounts",
    "GroupDetail",
    "GroupRef",
    "GroupSummary",
    "UserDetail",
    "UserRef",
    "UserSummary",
    "UserUpdate",
]
