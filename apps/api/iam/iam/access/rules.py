"""Working out which groups somebody's attributes put them in.

The joiner and mover half of the lifecycle. Somebody arrives in Engineering and
lands in the Engineering group; somebody moves to Sales and stops being in it.

Reconciling, not adding
-----------------------

``reconcile`` computes the whole set of groups the rules want for one person and
makes the database match. That matters more than it sounds: a function that only
added memberships would handle the joiner and get the mover exactly wrong,
leaving somebody who transferred out of Engineering still in its group forever.
Movers are the case that goes unnoticed, so the operation is "make it match", not
"grant".

Only touching what it owns
--------------------------

It adds and removes rows with ``source = rule`` and nothing else. Memberships the
provider sent, or that somebody added by hand, are read but never removed.

That is not politeness, it is the difference between working and looping. Delete a
membership authentik believes in and the next sync recreates it, then the next
reconcile removes it again, forever — with an audit entry each way. The
``source`` column on GroupMember exists for exactly this.

The other half of the same rule: if somebody is already in a group because the
provider put them there, and a rule also wants them in it, nothing happens. The
primary key stops a second row, and when the rule stops applying their
provider-granted membership is still there — which is right, because the provider
still wants it.
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
        # Refused rather than ignored. A rule reading "job title is set: Manager"
        # looks like it checks for Manager, and silently doesn't.
        raise RuleRefused(
            f"{operator} takes no value, but one was given. Leave it empty, or the "
            "rule will read as though it checks for that value."
        )


def matches(rule: AccessRule, user: User) -> bool:
    """Whether this rule applies to this person.

    Comparisons are case-insensitive and ignore surrounding spaces, because these
    values arrive from an HR system by way of a provider and "Engineering",
    "engineering" and " Engineering " all mean the same department. Being strict
    here would mean rules that work for most of a company and silently skip the
    people whose record was typed slightly differently.
    """
    actual = getattr(user, rule.attribute, None)
    present = actual is not None and str(actual).strip() != ""

    if rule.operator == RuleOperator.IS_SET:
        return present
    if rule.operator == RuleOperator.IS_NOT_SET:
        return not present

    if not present:
        # Nothing to compare. Notably this makes NOT_EQUALS false for somebody with
        # no department at all, rather than true — "department is not Sales" should
        # describe people who have a department, not people who have none.
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

    # Unreachable, and mypy proves it: every operator above is handled, so this
    # line only becomes reachable if somebody adds one to the enum. assert_never
    # then fails the type check rather than letting a new operator quietly match
    # nobody — or, worse, everybody. A runtime log here would have found that out
    # in production instead.
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

    The gate on the update paths. A provider re-syncs everybody on a schedule, and
    most of those writes touch a display name or a timestamp — running the engine
    for each one would be three extra queries per person per sync to reach the same
    answer. Changing a field no rule reads cannot change the outcome.

    A rule being created or edited is the other way round, and does not come
    through here: nobody's attributes changed, so use ``reconcile_group``.
    """
    return bool(set(fields) & set(ATTRIBUTES))


async def matching_rules(db: AsyncSession, user: User) -> list[AccessRule]:
    """Every enabled rule that applies to this person.

    Loads the rules and compares in Python rather than building SQL conditions.
    There are a handful of rules and the matching is string comparison, so the
    clarity is worth more than the query — and `matches` stays a plain function
    that a test can call with two objects.
    """
    rules = (await db.scalars(select(AccessRule).where(AccessRule.enabled))).all()
    return [rule for rule in rules if matches(rule, user)]


async def reconcile(db: AsyncSession, user: User) -> Reconciliation:
    """Make this person's rule-granted group membership match the rules.

    Adds what the rules now want, removes what they no longer want, and leaves
    everything it doesn't own alone.

    A deactivated person gets nothing added. Their rule-granted memberships are
    still removed, so somebody who has left stops appearing in the group listings
    a reviewer reads — but see iam/access/lifecycle.py, which deliberately leaves
    provider-granted membership in place for a leaver.

    Reactivating somebody does let the rules grant again, which looks like it
    contradicts lifecycle.py saying nothing comes back. It doesn't, and the
    difference is worth being precise about. A role grant and a direct application
    assignment were decisions somebody made once, and a rehire should not silently
    inherit a decision made about a different job two years ago. A rule is not a
    past decision — it is a standing statement that anybody with this attribute
    belongs in this group. If they still have the attribute, the rule still means
    it, and refusing would make the rule inconsistent with itself.
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

    # Groups they are in for any reason at all. A rule wanting one of these has
    # nothing to do: they are already in it, and the primary key would refuse a
    # second row anyway.
    already_in = set(
        (await db.scalars(select(GroupMember.group_id).where(GroupMember.user_id == user.id))).all()
    )

    to_add = wanted - already_in
    to_remove = mine - wanted

    names = await _group_names(db, to_add | to_remove)

    # One row per group, not per rule. Two rules can point at the same group —
    # that is how conditions compose without a boolean language — and iterating
    # over the rules would try to insert the same membership twice and hit the
    # primary key. The membership records the first rule that wanted it, and stays
    # while any of them still does, because `wanted` is a set.
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
                # Belt and braces. to_remove is already only rule-sourced rows, and
                # this makes it impossible for a future edit to widen that by
                # accident.
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
    # .tuples() rather than .all(): it gives the rows a real tuple type, which is
    # what lets this be a plain dict() that both ruff and mypy are happy with.
    return dict(rows.tuples().all())


async def affected_by(db: AsyncSession, rule: AccessRule) -> list[User]:
    """Everybody a rule currently applies to.

    For the console's "who would this affect" preview, which is the difference
    between writing a rule confidently and writing one and hoping. Reads active
    people only, since a rule grants nothing to somebody who has left.
    """
    users = (await db.scalars(select(User).where(User.active))).all()
    return [user for user in users if matches(rule, user)]


async def reconcile_group(db: AsyncSession, rule: AccessRule) -> Reconciliation:
    """Bring one rule's group into line for everybody, after the rule changed.

    Writing a rule should take effect without waiting for each person's next
    attribute change, and disabling one should take back what it granted. This
    walks everybody, which is fine at this size and is honest about being a full
    pass rather than pretending to be incremental.
    """
    users = (await db.scalars(select(User))).all()

    added: list[str] = []
    removed: list[str] = []
    for user in users:
        outcome = await reconcile(db, user)
        added.extend(f"{user.user_name} -> {name}" for name in outcome.added)
        removed.extend(f"{user.user_name} -> {name}" for name in outcome.removed)

    return Reconciliation(added=tuple(added), removed=tuple(removed), matched_rules=(rule.name,))
