"""The shapes the API sends and accepts.

Kept separate from iam.models: those describe the database, these describe
the wire format. Otherwise a column rename would break clients, and a new
column would get published without anyone deciding to.
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
