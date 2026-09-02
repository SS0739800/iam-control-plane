"""a lease so two syncs cannot run at once

The worker's own docstring claimed it never ran more than one sweep at a time. That
was true within a process — the loop is sequential — and false across machines. Two
worker machines, a deploy that briefly overlaps them, or a manual "Sync now" landing
while the sweep is mid-run, and two reconciles work the same links at the same time.

The damage was bounded: one_account_per_person stops duplicate links, and a 409 on
create is adopted rather than treated as a failure. So it would converge — by
adopting an account it had half-created itself, with two correlation ids interleaved
through the audit log. Correct in the end and unreadable on the way there.

Why a column and not an advisory lock
-------------------------------------

pg_advisory_xact_lock is the usual answer and cannot work here. reconcile() commits
between every person on purpose, so that the audit chain's lock is never held across
a network call — which means a transaction-scoped lock ends at the first person. A
session-scoped one survives commits but travels with a connection, and through a
transaction-mode pooler the next transaction may land on a different backend.

A lease on the row has neither problem. It survives commits because it is data, it
does not care which backend holds it, and it expires — so a worker killed mid-sweep
releases it by doing nothing.

Revision ID: 7a2e4b91c5d3
Revises: 3f1c9a24e7b8
Create Date: 2026-09-02 18:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7a2e4b91c5d3"
down_revision: str | None = "3f1c9a24e7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "provisioning_targets",
        sa.Column(
            "sweep_lease_until",
            sa.DateTime(timezone=True),
            nullable=True,
            comment=(
                "Held while a sync is running against this target, so two of them "
                "cannot run at once. Expires on its own, so a worker dying mid-sweep "
                "does not wedge the target."
            ),
        ),
    )


def downgrade() -> None:
    op.drop_column("provisioning_targets", "sweep_lease_until")
