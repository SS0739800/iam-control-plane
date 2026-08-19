"""Tests for rules that grant group membership from somebody's attributes.

Three things are being checked, in rising order of how much they matter.

That the comparisons work — including the awkward ones, like what "department is
not Sales" should mean for somebody with no department at all.

That the mover case works. A rule engine that only adds memberships passes every
joiner test and leaves somebody who transferred out of Engineering in its group
forever.

That it never touches a membership it doesn't own. Delete a row the provider
believes in and the next sync recreates it, then the next reconcile removes it
again, forever. The test at the end runs both directions and checks the row
survives.

The matching tests need no database. The rest do, and skip without
IAM_TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.access.rules import RuleRefused, matches, reconcile, validate
from iam.models.enums import (
    IdentitySource,
    MembershipSource,
    PlatformRole,
    RuleOperator,
)
from iam.models.group import Group, GroupMember
from iam.models.rules import AccessRule
from iam.models.user import User


def make_rule(
    *,
    attribute: str = "department",
    operator: RuleOperator = RuleOperator.EQUALS,
    value: str | None = "Engineering",
    group_id: uuid.UUID | None = None,
    name: str | None = None,
) -> AccessRule:
    return AccessRule(
        name=name or f"rule-{uuid.uuid4().hex[:8]}",
        attribute=attribute,
        operator=operator,
        value=value,
        group_id=group_id or uuid.uuid4(),
        created_by_label="a test",
        enabled=True,
    )


def make_person(**fields: object) -> User:
    defaults: dict[str, object] = {
        "user_name": "ada@demo.local",
        "email": "ada@demo.local",
        "display_name": "Ada Bergman",
        "active": True,
        "platform_role": PlatformRole.EMPLOYEE,
        "source": IdentitySource.SCIM,
    }
    defaults.update(fields)
    return User(**defaults)


# ------------------------------------------------------------- the comparisons


def test_equals_matches() -> None:
    assert matches(make_rule(value="Engineering"), make_person(department="Engineering"))


def test_equals_ignores_case_and_spaces() -> None:
    """These values come from an HR system by way of a provider. Being strict would
    mean rules that work for most of a company and silently skip whoever's record
    was typed with a trailing space."""
    rule = make_rule(value="engineering")

    assert matches(rule, make_person(department="  Engineering  "))
    assert matches(rule, make_person(department="ENGINEERING"))


def test_equals_does_not_match_something_else() -> None:
    assert not matches(make_rule(value="Engineering"), make_person(department="Sales"))


def test_contains_and_starts_with() -> None:
    person = make_person(job_title="Senior Platform Engineer")

    assert matches(
        make_rule(attribute="job_title", operator=RuleOperator.CONTAINS, value="Platform"),
        person,
    )
    assert matches(
        make_rule(attribute="job_title", operator=RuleOperator.STARTS_WITH, value="Senior"),
        person,
    )
    assert not matches(
        make_rule(attribute="job_title", operator=RuleOperator.STARTS_WITH, value="Platform"),
        person,
    )


def test_is_set_and_is_not_set() -> None:
    with_dept = make_person(department="Sales")
    without = make_person(department=None)
    blank = make_person(department="   ")

    is_set = make_rule(operator=RuleOperator.IS_SET, value=None)
    is_not_set = make_rule(operator=RuleOperator.IS_NOT_SET, value=None)

    assert matches(is_set, with_dept)
    assert not matches(is_set, without)
    # Whitespace is not a value. A record with a space in the department field is
    # somebody whose department was never filled in.
    assert not matches(is_set, blank)
    assert matches(is_not_set, without)


def test_not_equals_does_not_match_somebody_with_no_value() -> None:
    """The awkward one. "Department is not Sales" should describe people who have a
    department, not people who have none — otherwise a rule aimed at everybody
    outside Sales also catches every record with a blank field."""
    rule = make_rule(operator=RuleOperator.NOT_EQUALS, value="Sales")

    assert matches(rule, make_person(department="Engineering"))
    assert not matches(rule, make_person(department="Sales"))
    assert not matches(rule, make_person(department=None))


# ------------------------------------------------------------ writing a rule


def test_a_rule_cannot_read_any_column_it_likes() -> None:
    """A rule reading platform_role would make group membership depend on console
    privilege, which is backwards. One reading token_hash should be unthinkable."""
    with pytest.raises(RuleRefused, match="can't look at"):
        validate("platform_role", RuleOperator.EQUALS, "admin")

    with pytest.raises(RuleRefused, match="can't look at"):
        validate("token_hash", RuleOperator.EQUALS, "anything")


def test_a_comparison_needs_something_to_compare() -> None:
    with pytest.raises(RuleRefused, match="needs a value"):
        validate("department", RuleOperator.EQUALS, "")


def test_a_valueless_operator_refuses_a_value() -> None:
    """ "Job title is set: Manager" looks like it checks for Manager and doesn't.
    Refused rather than ignored."""
    with pytest.raises(RuleRefused, match="takes no value"):
        validate("job_title", RuleOperator.IS_SET, "Manager")


def test_a_good_rule_validates() -> None:
    validate("department", RuleOperator.EQUALS, "Engineering")
    validate("job_title", RuleOperator.IS_SET, None)


def test_the_rule_reads_as_a_sentence() -> None:
    """It goes in the console and the audit log, so it has to be readable."""
    assert make_rule(value="Engineering").sentence == "Department is 'Engineering'"
    assert (
        make_rule(attribute="job_title", operator=RuleOperator.IS_SET, value=None).sentence
        == "Job title has any value"
    )


# ------------------------------------------------------------- reconciling

pytestmark_db = pytest.mark.integration


async def setup_group(db: AsyncSession, label: str) -> Group:
    group = Group(name=f"{label}-{uuid.uuid4().hex[:8]}", source=IdentitySource.MANUAL)
    db.add(group)
    await db.flush()
    return group


async def setup_person(db: AsyncSession, **fields: object) -> User:
    suffix = uuid.uuid4().hex[:12]
    person = make_person(
        user_name=f"rules.{suffix}@demo.local",
        email=f"rules.{suffix}@demo.local",
        display_name=f"Rules Tester {suffix}",
        **fields,
    )
    db.add(person)
    await db.flush()
    return person


async def setup_rule(db: AsyncSession, group: Group, **kwargs: object) -> AccessRule:
    rule = make_rule(group_id=group.id, **kwargs)  # type: ignore[arg-type]
    db.add(rule)
    await db.flush()
    return rule


async def memberships(db: AsyncSession, user: User) -> dict[uuid.UUID, MembershipSource]:
    rows = await db.execute(
        select(GroupMember.group_id, GroupMember.source).where(GroupMember.user_id == user.id)
    )
    return dict(rows.tuples().all())


@pytest.mark.integration
async def test_a_joiner_lands_in_the_group(db_session: AsyncSession) -> None:
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Engineering")

    outcome = await reconcile(db_session, person)

    assert outcome.added == (group.name,)
    assert (await memberships(db_session, person))[group.id] == MembershipSource.RULE


@pytest.mark.integration
async def test_somebody_who_does_not_match_gets_nothing(db_session: AsyncSession) -> None:
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Sales")

    outcome = await reconcile(db_session, person)

    assert outcome.added == ()
    assert await memberships(db_session, person) == {}


@pytest.mark.integration
async def test_a_mover_loses_the_group_they_left(db_session: AsyncSession) -> None:
    """The case an add-only engine gets silently wrong, and the reason this
    function reconciles instead of granting."""
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Engineering")
    await reconcile(db_session, person)

    person.department = "Sales"
    await db_session.flush()
    outcome = await reconcile(db_session, person)

    assert outcome.removed == (group.name,)
    assert await memberships(db_session, person) == {}


@pytest.mark.integration
async def test_a_mover_swaps_one_group_for_another(db_session: AsyncSession) -> None:
    engineering = await setup_group(db_session, "engineering")
    sales = await setup_group(db_session, "sales")
    await setup_rule(db_session, engineering, value="Engineering")
    await setup_rule(db_session, sales, value="Sales")
    person = await setup_person(db_session, department="Engineering")
    await reconcile(db_session, person)

    person.department = "Sales"
    await db_session.flush()
    outcome = await reconcile(db_session, person)

    assert outcome.added == (sales.name,)
    assert outcome.removed == (engineering.name,)
    assert set(await memberships(db_session, person)) == {sales.id}


@pytest.mark.integration
async def test_reconciling_twice_changes_nothing_the_second_time(
    db_session: AsyncSession,
) -> None:
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Engineering")

    first = await reconcile(db_session, person)
    second = await reconcile(db_session, person)

    assert first.changed is True
    assert second.changed is False


@pytest.mark.integration
async def test_a_disabled_rule_takes_back_what_it_granted(db_session: AsyncSession) -> None:
    group = await setup_group(db_session, "engineering")
    rule = await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Engineering")
    await reconcile(db_session, person)

    rule.enabled = False
    await db_session.flush()
    outcome = await reconcile(db_session, person)

    assert outcome.removed == (group.name,)


@pytest.mark.integration
async def test_a_deactivated_person_is_granted_nothing(db_session: AsyncSession) -> None:
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    person = await setup_person(db_session, department="Engineering", active=False)

    outcome = await reconcile(db_session, person)

    assert outcome.added == ()


# ------------------------------------------- not touching what it doesn't own


@pytest.mark.integration
async def test_a_membership_the_provider_sent_is_left_alone(
    db_session: AsyncSession,
) -> None:
    """The provider owns that row. Removing it starts a fight with the next sync."""
    group = await setup_group(db_session, "vpn-users")
    person = await setup_person(db_session, department="Engineering")
    db_session.add(GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.SCIM))
    await db_session.flush()

    # A rule that matches this person but has nothing to do with that group.
    other = await setup_group(db_session, "engineering")
    await setup_rule(db_session, other, value="Engineering")

    await reconcile(db_session, person)

    assert (await memberships(db_session, person))[group.id] == MembershipSource.SCIM


@pytest.mark.integration
async def test_a_membership_somebody_added_by_hand_is_left_alone(
    db_session: AsyncSession,
) -> None:
    group = await setup_group(db_session, "special-cases")
    person = await setup_person(db_session, department="Sales")
    db_session.add(
        GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.MANUAL)
    )
    await db_session.flush()

    await reconcile(db_session, person)

    assert (await memberships(db_session, person))[group.id] == MembershipSource.MANUAL


@pytest.mark.integration
async def test_the_engine_does_not_fight_the_sync(db_session: AsyncSession) -> None:
    """The loop this whole design exists to avoid.

    Somebody is in a group because the provider put them there, and a rule wants
    them in it too. Nothing should be added — they are already in it — and when the
    rule stops applying, the provider's row must still be there. Otherwise:
    reconcile removes it, the sync recreates it, reconcile removes it again, with
    an audit entry each way, forever.
    """
    group = await setup_group(db_session, "engineering")
    person = await setup_person(db_session, department="Engineering")
    db_session.add(GroupMember(group_id=group.id, user_id=person.id, source=MembershipSource.SCIM))
    await db_session.flush()

    await setup_rule(db_session, group, value="Engineering")

    # The rule wants what the provider already gave. Nothing to do.
    first = await reconcile(db_session, person)
    assert first.added == ()
    assert (await memberships(db_session, person))[group.id] == MembershipSource.SCIM

    # They transfer out. The rule no longer applies — but that row was never ours.
    person.department = "Sales"
    await db_session.flush()
    second = await reconcile(db_session, person)

    assert second.removed == ()
    assert (await memberships(db_session, person))[group.id] == MembershipSource.SCIM


@pytest.mark.integration
async def test_two_rules_can_share_a_group(db_session: AsyncSession) -> None:
    """Rules compose instead of needing a boolean language. One is enough to keep
    somebody in, and losing one doesn't remove them."""
    group = await setup_group(db_session, "engineering")
    await setup_rule(db_session, group, value="Engineering")
    await setup_rule(
        db_session, group, attribute="job_title", operator=RuleOperator.CONTAINS, value="Engineer"
    )
    person = await setup_person(db_session, department="Engineering", job_title="Data Engineer")

    await reconcile(db_session, person)
    assert set(await memberships(db_session, person)) == {group.id}

    # Only one of the two stops applying.
    person.department = "Sales"
    await db_session.flush()
    outcome = await reconcile(db_session, person)

    assert outcome.removed == ()
    assert set(await memberships(db_session, person)) == {group.id}
