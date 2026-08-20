"""drop push_groups from provisioning targets

The flag was stored, returned by the API, and settable by POST and PATCH. Nothing
ever read it. iam/provisioning/sync.py pushes accounts and only accounts, so turning
it on did exactly nothing and said nothing about having done nothing.

That is worse than not having the field. Somebody switches it on, gets a 200 back,
and reasonably concludes group membership is now flowing downstream. A missing
feature is visible; a switch that lies is not.

So it goes, and it can come back with the code that honours it. Pushing groups is
not a small addition — a downstream group has its own lifecycle, its own reconcile,
and its own answer to "what if this system has no concept of a group" — which makes
it work in its own right rather than a boolean somebody forgot to wire up.

Dropping rather than keeping it nullable and ignored: the column has no data worth
preserving, because a value nothing read is not data. Anyone who set it to true set
it to true about nothing.

Revision ID: 3f1c9a24e7b8
Revises: c4ee55d399f1
Create Date: 2026-08-20 05:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3f1c9a24e7b8"
down_revision: str | None = "c4ee55d399f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("provisioning_targets", "push_groups")


def downgrade() -> None:
    """Put the column back, with the comment it had.

    Reversible on the schema, not on the intent: everything comes back false, which
    is what it effectively was anyway.
    """
    op.add_column(
        "provisioning_targets",
        sa.Column(
            "push_groups",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
            comment=(
                "Whether to push group membership as well as accounts. Off by default: "
                "plenty of downstreams have no concept of a group, and sending them one "
                "is an error per person per sync."
            ),
        ),
    )
