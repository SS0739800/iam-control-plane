"""Working out which groups somebody's attributes put them in.

The joiner and mover half of the lifecycle. Somebody arrives in Engineering
and lands in the Engineering group; somebody moves to Sales and stops being
in it.

``reconcile`` computes the full set of groups the rules want for one person
and makes the database match — adding and removing, not just adding. A
function that only added memberships would handle joiners fine but get
movers wrong, leaving someone who transferred out of Engineering stuck in
its group forever.

It only touches rows with ``source = rule``. Memberships the provider sent,
or that someone added by hand, are read but never removed — deleting a
membership the provider believes in would just have the next sync recreate
it, forever, with an audit entry each time. If a rule and the provider both
want someone in the same group, nothing happens either way: the primary key
blocks a duplicate row, and when the rule stops applying, the
provider-granted membership stays because the provider still wants it.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Iterable
from typing import assert_never

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.enums import MembershipSource, RuleOperator
from iam.models.group import Group, GroupMember
from iam.models.rules import ATTRIBUTES, VALUELESS_OPERATORS, AccessRule
from iam.models.user import User

logger = logging.getLogger(__name__)


class RuleRefused(Exception):
    """The rule doesn't make sense, and the message says why."""


def validate(attribute: str, operator: RuleOperator, value: str | None) -> None:
    """Check a rule is coherent before it is stored.

    Raises:
        RuleRefused: The attribute isn't one a rule may read, or the operator and
            value disagree about whether there should be one.
    """
    if attribute not in ATTRIBUTES:
        allowed = ", ".join(sorted(ATTRIBUTES))
        raise RuleRefused(f"A rule can't look at {attribute!r}. Allowed attributes: {allowed}.")

    needs_value = operator not in VALUELESS_OPERATORS

    if needs_value and not (value or "").strip():
        raise RuleRefused(f"{operator} needs a value to compare against.")

    if not needs_value and (value or "").strip():
        # Refused, not ignored — a rule reading "job title is set: Manager"
        # looks like it checks for Manager, but wouldn't.
        raise RuleRefused(
            f"{operator} takes no value, but one was given. Leave it empty, or the "
            "rule will read as though it checks for that value."
        )


def matches(rule: AccessRule, user: User) -> bool:
    """Whether this rule applies to this person.

    Comparisons are case-insensitive and trim spaces, since values come from
    an HR system through a provider and "Engineering", "engineering", and
    " Engineering " all mean the same department.
    """
    actual = getattr(user, rule.attribute, None)
    present = actual is not None and str(actual).strip() != ""

    if rule.operator == RuleOperator.IS_SET:
        return present
    if rule.operator == RuleOperator.IS_NOT_SET:
        return not present

    if not present:
        # Nothing to compare, so NOT_EQUALS is false here too — "department is
        # not Sales" should mean people who have a department, not people
        # with none.
        return False

    left = str(actual).strip().casefold()
    right = (rule.value or "").strip().casefold()

    if rule.operator == RuleOperator.EQUALS:
        return left == right
    if rule.operator == RuleOperator.NOT_EQUALS:
        return left != right
    if rule.operator == RuleOperator.CONTAINS:
        return right in left
    if rule.operator == RuleOperator.STARTS_WITH:
        return left.startswith(right)

    # Unreachable — every operator is handled above. assert_never turns adding
    # a new operator into a type error instead of a silent bug where it
    # matches nobody, or everybody.
    assert_never(rule.operator)


@dataclasses.dataclass(frozen=True, slots=True)
class Reconciliation:
    """What reconciling one person's rule-granted groups actually did."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    matched_rules: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    def as_audit_detail(self) -> dict[str, object]:
        return {
            "groups_added": list(self.added),
            "groups_removed": list(self.removed),
            "rules_matched": list(self.matched_rules),
        }


def touches_rules(fields: Iterable[str]) -> bool:
    """Whether a change to these fields could alter what the rules want.

    Used to skip re-running the engine on syncs that only touch a display
    name or timestamp — those can't change the outcome, so there's no need
    for extra queries per person.

    When a rule itself is created or edited, use ``reconcile_group``
    instead — nobody's attributes changed here.
    """
    return bool(set(fields) & set(ATTRIBUTES))


async def matching_rules(db: AsyncSession, user: User) -> list[AccessRule]:
    """Every enabled rule that applies to this person.

    Loads the rules and compares in Python rather than building SQL
    conditions — there are only a handful, and this keeps `matches` a plain
    function a test can call directly.
    """
    rules = (await db.scalars(select(AccessRule).where(AccessRule.enabled))).all()
    return [rule for rule in rules if matches(rule, user)]


async def reconcile(db: AsyncSession, user: User) -> Reconciliation:
    """Make this person's rule-granted group membership match the rules.

    Adds what the rules now want, removes what they no longer want, and
    leaves everything else alone.

    A deactivated person gets nothing added, and their rule-granted
    memberships are removed (provider-granted ones stay — see
    lifecycle.py).

    Reactivating someone lets rules grant access again, which isn't the
    same as lifecycle.py's "nothing comes back automatically." A role grant
    or direct assignment was a one-time decision, and a rehire shouldn't
    silently inherit one made for a different job years ago. A rule isn't a
    past decision, though — it's a standing statement ("anyone with this
    attribute belongs in this group"), so if the attribute is still true,
    the rule still applies.
    """
    applicable = await matching_rules(db, user)
    wanted: set[uuid.UUID] = set() if not user.active else {rule.group_id for rule in applicable}

    # Only the rows this engine owns. Everything else is somebody else's business.
    mine = set(
        (
            await db.scalars(
                select(GroupMember.group_id).where(
                    GroupMember.user_id == user.id,
                    GroupMember.source == MembershipSource.RULE,
                )
            )
        ).all()
    )

    # Groups they're already in for any reason — a rule wanting one of these
    # is a no-op, and the primary key would block a duplicate row anyway.
    already_in = set(
        (await db.scalars(select(GroupMember.group_id).where(GroupMember.user_id == user.id))).all()
    )

    to_add = wanted - already_in
    to_remove = mine - wanted

    names = await _group_names(db, to_add | to_remove)

    # One row per group, not per rule. Two rules can point at the same group,
    # so iterating over rules directly would try to insert the same
    # membership twice. It records the first rule that wanted it and stays
    # as long as any rule still does, since `wanted` is a set.
    attributed_to: dict[uuid.UUID, uuid.UUID] = {}
    for rule in applicable:
        attributed_to.setdefault(rule.group_id, rule.id)

    for group_id in to_add:
        db.add(
            GroupMember(
                group_id=group_id,
                user_id=user.id,
                source=MembershipSource.RULE,
                added_by_rule_id=attributed_to[group_id],
            )
        )

    if to_remove:
        await db.execute(
            delete(GroupMember).where(
                GroupMember.user_id == user.id,
                GroupMember.group_id.in_(to_remove),
                # Extra safety: to_remove is already rule-sourced only, this
                # just guards against a future edit widening it by accident.
                GroupMember.source == MembershipSource.RULE,
            )
        )

    await db.flush()

    result = Reconciliation(
        added=tuple(sorted(names.get(group_id, str(group_id)) for group_id in to_add)),
        removed=tuple(sorted(names.get(group_id, str(group_id)) for group_id in to_remove)),
        matched_rules=tuple(sorted(rule.name for rule in applicable)),
    )

    if result.changed:
        logger.info(
            "rules.reconciled",
            extra={"user_name": user.user_name, **result.as_audit_detail()},
        )

    return result


async def _group_names(db: AsyncSession, group_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    """Names for the groups that changed, so the audit entry reads as words."""
    if not group_ids:
        return {}
    rows = await db.execute(select(Group.id, Group.name).where(Group.id.in_(group_ids)))
    # .tuples() gives a real tuple type, so dict() works cleanly for both
    # ruff and mypy.
    return dict(rows.tuples().all())


async def affected_by(db: AsyncSession, rule: AccessRule) -> list[User]:
    """Everybody a rule currently applies to. Used for the console's "who
    would this affect" preview. Reads active people only, since a rule
    grants nothing to somebody who has left.
    """
    users = (await db.scalars(select(User).where(User.active))).all()
    return [user for user in users if matches(rule, user)]


async def reconcile_group(db: AsyncSession, rule: AccessRule) -> Reconciliation:
    """Bring one rule's group into line for everybody, after the rule changed.

    A new or edited rule should take effect immediately rather than waiting
    for each person's next attribute change. This walks every user, which
    is fine at this scale.
    """
    users = (await db.scalars(select(User))).all()

    added: list[str] = []
    removed: list[str] = []
    for user in users:
        outcome = await reconcile(db, user)
        added.extend(f"{user.user_name} -> {name}" for name in outcome.added)
        removed.extend(f"{user.user_name} -> {name}" for name in outcome.removed)

    return Reconciliation(added=tuple(added), removed=tuple(removed), matched_rules=(rule.name,))
