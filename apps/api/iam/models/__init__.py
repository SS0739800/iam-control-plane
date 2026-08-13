"""SQLAlchemy models.

Every model module must be imported here. Alembic's env.py reads
``Base.metadata`` to autogenerate migrations, and a model that is never imported
is invisible to it — which shows up as an empty migration rather than an error.

P1 adds: users, groups, group_members, applications, app_assignments,
audit_events.
"""

from __future__ import annotations

from iam.models.base import Base

__all__ = ["Base"]
