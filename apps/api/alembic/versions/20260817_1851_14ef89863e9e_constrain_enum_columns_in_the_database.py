"""constrain enum columns in the database

Every enum column in this schema was an unconstrained VARCHAR(32). SQLAlchemy
validated values on the way in, so nothing written through the ORM could be wrong,
but Postgres itself would accept anything — and iam/models/enums.py had claimed
otherwise since P1.

It was measured rather than assumed:

    UPDATE users SET platform_role = 'not-a-real-role';   -- succeeded

An unrecognised role reads as no permissions, because permissions_for falls back to
an empty set, so this failed safe. It also failed silently, which is the reason the
ORM check on its own was not enough: a migration, a psql session, or a future
background job writing SQL directly had nothing stopping it.

create_constraint=True in enum_type() covers every column added from here on. This
migration covers the twelve that already existed.

The constraints are generated from the enum definitions rather than typed out, so
the listed values cannot drift from the Python. Existing data was checked against
each one before this was written; nothing violated them.

Revision ID: 14ef89863e9e
Revises: 50c7528efa91
Create Date: 2026-08-17 18:51:34.827162+00:00

"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "14ef89863e9e"
down_revision: str | None = "50c7528efa91"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "appprotocol",
        "applications",
        "protocol IN ('saml2', 'oidc', 'scim2', 'none')",
    )
    op.create_check_constraint(
        "appstatus",
        "applications",
        "status IN ('active', 'inactive')",
    )
    op.create_check_constraint(
        "actortype",
        "audit_events",
        "actor_type IN ('user', 'system', 'idp')",
    )
    op.create_check_constraint(
        "auditoutcome",
        "audit_events",
        "outcome IN ('success', 'failure', 'denied')",
    )
    op.create_check_constraint(
        "identitysource",
        "groups",
        "source IN ('scim', 'jit', 'manual', 'seed')",
    )
    op.create_check_constraint(
        "platformrole",
        "users",
        "platform_role IN ('admin', 'helpdesk', 'auditor', 'employee')",
    )
    op.create_check_constraint(
        "identitysource",
        "users",
        "source IN ('scim', 'jit', 'manual', 'seed')",
    )
    op.create_check_constraint(
        "requeststate",
        "access_requests",
        "state IN ('pending', 'approved', 'denied', 'withdrawn', 'cancelled')",
    )
    op.create_check_constraint(
        "ruleoperator",
        "access_rules",
        "operator IN ('equals', 'not_equals', 'contains', 'starts_with', 'is_set', 'is_not_set')",
    )
    op.create_check_constraint(
        "platformrole",
        "role_grants",
        "role IN ('admin', 'helpdesk', 'auditor', 'employee')",
    )
    op.create_check_constraint(
        "grantsource",
        "role_grants",
        "source IN ('direct', 'rule', 'request', 'seed', 'migrated')",
    )
    op.create_check_constraint(
        "membershipsource",
        "group_members",
        "source IN ('scim', 'manual', 'rule', 'request', 'seed')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_applications_appprotocol", "applications", type_="check")
    op.drop_constraint("ck_applications_appstatus", "applications", type_="check")
    op.drop_constraint("ck_audit_events_actortype", "audit_events", type_="check")
    op.drop_constraint("ck_audit_events_auditoutcome", "audit_events", type_="check")
    op.drop_constraint("ck_groups_identitysource", "groups", type_="check")
    op.drop_constraint("ck_users_platformrole", "users", type_="check")
    op.drop_constraint("ck_users_identitysource", "users", type_="check")
    op.drop_constraint("ck_access_requests_requeststate", "access_requests", type_="check")
    op.drop_constraint("ck_access_rules_ruleoperator", "access_rules", type_="check")
    op.drop_constraint("ck_role_grants_platformrole", "role_grants", type_="check")
    op.drop_constraint("ck_role_grants_grantsource", "role_grants", type_="check")
    op.drop_constraint("ck_group_members_membershipsource", "group_members", type_="check")
