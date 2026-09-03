"""Every enum column is constrained in the database, not just in the ORM.

SQLAlchemy validates values on the way in, so nothing written through the ORM
is ever wrong — but Postgres accepts anything, so a migration, a psql session,
or a background job writing SQL directly had nothing stopping it.

Generated from the model metadata rather than a hand-written list, so a new
enum column is covered the moment it's added.

Needs Postgres and skips without IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Enum as SAEnum
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import iam.models  # noqa: F401  — imported for the side effect of registering every table
from iam.models.base import Base

pytestmark = pytest.mark.integration


def enum_columns() -> list[tuple[str, str, str]]:
    """Every (table, column, enum name) that should carry a CHECK constraint."""
    found = []
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, SAEnum):
                found.append((table.name, column.name, column.type.name or ""))
    return found


def test_there_are_enum_columns_to_check() -> None:
    """Guards the two tests below from passing by looking at nothing."""
    assert len(enum_columns()) >= 12


@pytest.mark.parametrize(("table", "column", "enum_name"), enum_columns())
async def test_the_column_has_a_check_constraint(
    db_session: AsyncSession, table: str, column: str, enum_name: str
) -> None:
    """The constraint exists, and is named after the enum it came from."""
    present = await db_session.scalar(
        text(
            "SELECT count(*) FROM pg_constraint "
            "WHERE contype = 'c' AND conrelid = :table ::regclass AND conname = :name"
        ),
        {"table": table, "name": f"ck_{table}_{enum_name}"},
    )

    assert present == 1, (
        f"{table}.{column} has no CHECK constraint. Enum columns need "
        f"create_constraint=True in enum_type(), plus a migration for columns that "
        f"already exist."
    )


@pytest.mark.parametrize(("table", "column", "enum_name"), enum_columns())
async def test_the_constraint_lists_every_value_and_no_others(
    db_session: AsyncSession, table: str, column: str, enum_name: str
) -> None:
    """The constraint covers the right column and exactly the right values.

    Reads the definition rather than trying a bad write, since most of these
    tables are empty in a test database and `UPDATE ... SET col = 'rubbish'`
    on an empty table changes no rows and violates nothing.
    """
    definition = await db_session.scalar(
        text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE contype = 'c' AND conrelid = :table ::regclass AND conname = :name"
        ),
        {"table": table, "name": f"ck_{table}_{enum_name}"},
    )

    assert definition, f"no constraint definition found for {table}.{column}"
    assert column in definition, f"the constraint on {table} does not mention {column}"

    expected = _values_for(table, column)
    for value in expected:
        assert f"'{value}'" in definition, (
            f"{table}.{column} would reject the valid value {value!r} — the "
            f"constraint is out of step with the enum"
        )

    # And nothing extra. A constraint listing a value the enum dropped would let a
    # stale value back in.
    quoted = definition.count("'")
    assert quoted == len(expected) * 2, (
        f"{table}.{column} constrains {quoted // 2} values but the enum has "
        f"{len(expected)}: {definition}"
    )


async def test_a_bad_value_is_actually_rejected(db_session: AsyncSession) -> None:
    """One end-to-end proof: write a value Postgres should refuse.

    The definition tests above are thorough but indirect; this is the direct
    version, the exact UPDATE that succeeded before the constraints existed.

    Creates its own row first, since the test database isn't seeded — an
    UPDATE against zero rows changes nothing and violates nothing.
    """
    import uuid

    from sqlalchemy.exc import IntegrityError

    from iam.models.enums import IdentitySource, PlatformRole
    from iam.models.user import User

    suffix = uuid.uuid4().hex[:12]
    person = User(
        user_name=f"constraint.{suffix}@demo.local",
        email=f"constraint.{suffix}@demo.local",
        display_name="Constraint Tester",
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.MANUAL,
    )
    db_session.add(person)
    await db_session.flush()

    nested = await db_session.begin_nested()
    try:
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text("UPDATE users SET platform_role = 'not-a-real-role' WHERE id = :id"),
                {"id": person.id},
            )
    finally:
        if nested.is_active:
            await nested.rollback()


def _values_for(table: str, column: str) -> tuple[str, ...]:
    for candidate in Base.metadata.sorted_tables:
        if candidate.name != table:
            continue
        found = candidate.columns[column]
        assert isinstance(found.type, SAEnum)
        return tuple(found.type.enums)
    raise AssertionError(f"no table called {table}")
