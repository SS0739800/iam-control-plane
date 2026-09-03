"""Managing the rules that grant group membership from attributes.

Guarded by ``groups:write``, which is admin-only. A rule automates exactly
what someone with ``groups:write`` could already do by hand, to more people
at once, so it reuses that permission rather than inventing a new one.
(Role grants needed their own permission because ``users:write`` was *not*
an equivalent power — reuse a permission when the action really is the
same one, not just nearby.)

Every write here applies the rule immediately, against everybody. A rule
that only took effect on someone's next attribute change would look broken
for weeks, and disabling one has to take back what it granted.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from iam.access import RuleRefused, affected_by, reconcile_group, validate
from iam.audit import AuditDraft, append_event
from iam.deps import SessionDep
from iam.models.enums import ActorType, AuditOutcome, MembershipSource, RuleOperator
from iam.models.group import Group, GroupMember
from iam.models.rules import ATTRIBUTES, AccessRule
from iam.schemas.rules import (
    AccessRuleCreate,
    AccessRuleOut,
    AccessRuleUpdate,
    AffectedPerson,
    RuleAttribute,
    RulePreview,
    RuleRunResult,
)
from iam.security import Actor, Permission, require

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/access-rules", tags=["access rules"])

SAMPLE_SIZE = 8


async def _out(session: SessionDep, rule: AccessRule) -> AccessRuleOut:
    group = await session.get(Group, rule.group_id)
    members = (
        await session.scalar(
            select(func.count())
            .select_from(GroupMember)
            .where(
                GroupMember.group_id == rule.group_id,
                GroupMember.source == MembershipSource.RULE,
            )
        )
        or 0
    )
    return AccessRuleOut(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        enabled=rule.enabled,
        attribute=rule.attribute,
        operator=rule.operator,
        value=rule.value,
        group_id=rule.group_id,
        group_name=group.name if group else "(deleted group)",
        sentence=rule.sentence,
        member_count=members,
        created_by_label=rule.created_by_label,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


async def _load(session: SessionDep, rule_id: uuid.UUID) -> AccessRule:
    rule = await session.get(AccessRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No access rule with id {rule_id}.")
    return rule


async def _check(
    session: SessionDep,
    attribute: str,
    operator: RuleOperator,
    value: str | None,
    group_id: uuid.UUID,
) -> None:
    """Validate the condition and confirm the group exists.

    Raises:
        HTTPException: 400 for a condition that doesn't make sense, 404 for a group
            that isn't there.
    """
    try:
        validate(attribute, operator, value)
    except RuleRefused as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if await session.get(Group, group_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No group with id {group_id}.")


@router.get(
    "/attributes",
    response_model=list[RuleAttribute],
    summary="The fields a rule may look at",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def list_attributes() -> list[RuleAttribute]:
    """What a rule is allowed to read.

    A fixed list, not every column on the user. The console builds its dropdown
    from this so the two can't disagree about what is allowed.
    """
    return [RuleAttribute(name=name, label=label) for name, label in sorted(ATTRIBUTES.items())]


@router.get(
    "",
    response_model=list[AccessRuleOut],
    summary="Every access rule",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def list_rules(session: SessionDep) -> list[AccessRuleOut]:
    """All of them, disabled ones included.

    A disabled rule is part of the answer to "why did this person used to have
    that", so hiding it would make the screen less useful, not tidier.
    """
    rules = (await session.scalars(select(AccessRule).order_by(AccessRule.name))).all()
    return [await _out(session, rule) for rule in rules]


@router.post(
    "/preview",
    response_model=RulePreview,
    summary="Who would this rule affect?",
)
async def preview(
    payload: AccessRuleCreate,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> RulePreview:
    """Try a rule without saving it.

    Writes nothing. A condition that reads correctly and matches four hundred
    people usually means the value was mistyped, and this is where somebody notices
    before it becomes four hundred audit entries.
    """
    await _check(session, payload.attribute, payload.operator, payload.value, payload.group_id)

    # Built but never added to the session, so nothing can persist it by accident.
    candidate = AccessRule(
        name=payload.name,
        attribute=payload.attribute,
        operator=payload.operator,
        value=payload.value,
        group_id=payload.group_id,
        created_by_label=actor.audit_label,
        enabled=True,
    )

    people = await affected_by(session, candidate)

    already = set(
        (
            await session.scalars(
                select(GroupMember.user_id).where(GroupMember.group_id == payload.group_id)
            )
        ).all()
    )
    group = await session.get(Group, payload.group_id)

    return RulePreview(
        sentence=candidate.sentence,
        group_name=group.name if group else "(unknown)",
        matches=len(people),
        already_in_group=sum(1 for person in people if person.id in already),
        would_be_added=sum(1 for person in people if person.id not in already),
        sample=[AffectedPerson.model_validate(person) for person in people[:SAMPLE_SIZE]],
    )


@router.post(
    "",
    response_model=AccessRuleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Write a new rule and apply it",
)
async def create_rule(
    payload: AccessRuleCreate,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> AccessRuleOut:
    """Create a rule, then run it against everybody.

    Raises:
        HTTPException: 400 for a condition that doesn't make sense, 404 for a
            missing group, 409 if the same condition already grants that group.
    """
    await _check(session, payload.attribute, payload.operator, payload.value, payload.group_id)

    clash = await session.scalar(
        select(AccessRule).where(
            AccessRule.attribute == payload.attribute,
            AccessRule.operator == payload.operator,
            AccessRule.value == payload.value,
            AccessRule.group_id == payload.group_id,
        )
    )
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"{clash.name!r} already grants that group on the same condition. "
                "Two identical rules would both add the same people."
            ),
        )

    by_name = await session.scalar(select(AccessRule).where(AccessRule.name == payload.name))
    if by_name is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"A rule called {payload.name!r} already exists."
        )

    rule = AccessRule(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        attribute=payload.attribute,
        operator=payload.operator,
        value=payload.value,
        group_id=payload.group_id,
        created_by_label=actor.audit_label,
    )
    session.add(rule)
    await session.flush()

    outcome = await reconcile_group(session, rule)

    await append_event(
        session,
        AuditDraft(
            action="access_rule.created",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_rule",
            target_id=str(rule.id),
            target_label=rule.name,
            detail={
                "sentence": rule.sentence,
                "enabled": rule.enabled,
                # The full effect in one entry, so a rule that unexpectedly
                # moves two hundred people is visible here, not as two
                # hundred separate memberships.
                "granted_to": outcome.added[:50],
                "granted_count": len(outcome.added),
            },
        ),
    )
    await session.commit()
    await session.refresh(rule)

    logger.info(
        "access_rule.created",
        extra={"rule": rule.name, "by": actor.user_name, "granted": len(outcome.added)},
    )

    return await _out(session, rule)


@router.patch(
    "/{rule_id}",
    response_model=AccessRuleOut,
    summary="Change a rule and re-apply it",
)
async def update_rule(
    rule_id: uuid.UUID,
    payload: AccessRuleUpdate,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> AccessRuleOut:
    """Edit a rule, then bring everybody into line with it.

    Disabling a rule here takes back what it granted, which is the only reading of
    "disabled" that means anything.
    """
    rule = await _load(session, rule_id)
    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No fields to update.")

    before = {field: getattr(rule, field) for field in changes}
    for field, value in changes.items():
        setattr(rule, field, value)

    # Validated after applying, so a change to one half of the condition is checked
    # against the other half as it will actually be stored.
    await _check(session, rule.attribute, rule.operator, rule.value, rule.group_id)
    await session.flush()

    outcome = await reconcile_group(session, rule)

    await append_event(
        session,
        AuditDraft(
            action="access_rule.updated",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_rule",
            target_id=str(rule.id),
            target_label=rule.name,
            detail={
                "changed": {
                    field: {"from": str(before[field]), "to": str(getattr(rule, field))}
                    for field in changes
                },
                "sentence": rule.sentence,
                "granted_to": outcome.added[:50],
                "removed_from": outcome.removed[:50],
            },
        ),
    )
    await session.commit()
    await session.refresh(rule)

    return await _out(session, rule)


@router.delete(
    "/{rule_id}",
    response_model=RuleRunResult,
    summary="Delete a rule and take back what it granted",
)
async def delete_rule(
    rule_id: uuid.UUID,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> RuleRunResult:
    """Remove a rule, and remove the access it was giving people.

    Deleted rather than kept, unlike a role grant — a rule is a statement
    of intent, not a record of something that happened, and the audit
    entry already holds what it said.

    The memberships it granted are removed too. Leaving them would turn
    automatic access into permanent access that nothing explains.
    """
    rule = await _load(session, rule_id)
    sentence = rule.sentence
    name = rule.name

    # Disabled first, then reconciled, so the engine removes what only this
    # rule was granting before the row itself is deleted.
    rule.enabled = False
    await session.flush()
    outcome = await reconcile_group(session, rule)

    await session.delete(rule)

    await append_event(
        session,
        AuditDraft(
            action="access_rule.deleted",
            actor_type=ActorType.USER,
            actor_id=actor.user_id,
            actor_label=actor.audit_label,
            outcome=AuditOutcome.SUCCESS,
            target_type="access_rule",
            target_id=str(rule_id),
            target_label=name,
            detail={"sentence": sentence, "removed_from": outcome.removed[:50]},
        ),
    )
    await session.commit()

    logger.info(
        "access_rule.deleted",
        extra={"rule": name, "by": actor.user_name, "removed": len(outcome.removed)},
    )

    return RuleRunResult(
        added=list(outcome.added), removed=list(outcome.removed), unchanged=not outcome.changed
    )


@router.post(
    "/{rule_id}/run",
    response_model=RuleRunResult,
    summary="Apply this rule to everybody now",
)
async def run_rule(
    rule_id: uuid.UUID,
    session: SessionDep,
    actor: Annotated[Actor, Depends(require(Permission.GROUPS_WRITE))],
) -> RuleRunResult:
    """Re-run a rule over everybody.

    Normally unnecessary since writes apply immediately and attribute
    changes reconcile as they happen — this is for a direct database edit,
    or to confirm nothing has drifted. A run reporting no changes is the
    good outcome.
    """
    rule = await _load(session, rule_id)
    outcome = await reconcile_group(session, rule)

    if outcome.changed:
        await append_event(
            session,
            AuditDraft(
                action="access_rule.run",
                actor_type=ActorType.USER,
                actor_id=actor.user_id,
                actor_label=actor.audit_label,
                outcome=AuditOutcome.SUCCESS,
                target_type="access_rule",
                target_id=str(rule.id),
                target_label=rule.name,
                detail={
                    "granted_to": outcome.added[:50],
                    "removed_from": outcome.removed[:50],
                },
            ),
        )

    await session.commit()

    return RuleRunResult(
        added=list(outcome.added), removed=list(outcome.removed), unchanged=not outcome.changed
    )


@router.get(
    "/{rule_id}/affected",
    response_model=list[AffectedPerson],
    summary="Who this rule currently applies to",
    dependencies=[Depends(require(Permission.GROUPS_READ))],
)
async def affected(
    rule_id: uuid.UUID,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AffectedPerson]:
    """The people a rule matches right now."""
    rule = await _load(session, rule_id)
    people = await affected_by(session, rule)
    return [AffectedPerson.model_validate(person) for person in people[:limit]]
