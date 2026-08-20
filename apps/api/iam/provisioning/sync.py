"""Deciding what to push, and pushing it.

The client makes requests. This decides which requests to make, and it is the part
with the actual judgement in it.

Reconciling, not reacting
-------------------------

``reconcile`` works out the whole set of accounts a target should have and makes it
so. It does not take a list of changes.

That is the same shape as the access rules engine and for the same reason: a
change-driven pusher handles the joiner and gets the leaver wrong the first time a
message is lost, a process restarts mid-run, or somebody edits the database. Anything
that can drift needs something that can converge, and converging means computing the
whole answer.

Reacting is still worth doing on top — pushing one person immediately when their
access changes, rather than waiting for the next full pass — but it is an
optimisation over a correct baseline, not the baseline.

How staleness is detected without a new column
----------------------------------------------

A person needs re-pushing when their record changed after we last pushed it. That is
``user.updated_at > link.last_pushed_at``, which both tables already carry.

The alternative was storing a hash of the last payload. This is cheaper and has one
useful property a hash does not: a row touched with no real change still gets
re-pushed, which is the safe direction to be wrong in.

One run, one correlation id
---------------------------

Every audit entry a run produces carries the same ``correlation_id``. That column has
existed since P1 with a comment saying P6 would rely on it, and this is why: a sync
that creates forty accounts and fails on three is one event to a person and forty
three rows in the log. The id is what turns the second back into the first.

One transaction per person, not one per run
------------------------------------------

Every audit entry this module writes is committed as it is written, so the HTTP calls
happen with no database lock held. That is required rather than tidy, and finding out
why cost an afternoon.

``append_event`` takes ``pg_advisory_xact_lock`` and holds it until commit, because
the log is a hash chain and two writers would produce two rows claiming the same
predecessor. A run that kept one transaction open would therefore hold that lock
across every request it makes: one slow downstream would block every audit write in
the whole application, and pointing the sync at our own SCIM server deadlocks
outright — it holds the lock, then makes a request that needs it.

The commit lives inside ``_record`` rather than at the call sites, so the rule holds
by construction, and there is a second commit immediately before each push so that
nothing else — a freshly inserted link row, a read — is holding a transaction open
either. The invariant is simply: no open transaction while talking to a downstream.

The useful side effect is that a run interrupted halfway leaves the people it
finished done instead of rolling all of them back.

Failures do not stop the run, except one
----------------------------------------

A downstream refusing one person is that person's problem, and working through the
rest is right — otherwise one bad record blocks everybody behind it.

An authentication failure is different and stops immediately. The token is wrong, so
every remaining push will fail identically, and grinding through a thousand people to
collect a thousand copies of the same 401 helps nobody and looks like a retry storm
from the far end.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit import AuditDraft, append_event
from iam.config import Settings
from iam.models.application import AppAssignment
from iam.models.enums import ActorType, AuditOutcome, LinkState
from iam.models.group import GroupMember
from iam.models.provisioning import ProvisioningLink, ProvisioningTarget
from iam.models.user import User
from iam.provisioning.client import OutboundScim, PushFailed, user_payload
from iam.secrets import CannotDecrypt, decrypt

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
"""How many consecutive failures before a link stops being retried automatically.

Not a give-up so much as a stop-shouting. A link failing five times in a row is
failing for a reason a retry will not fix, and continuing to try it every run buries
the ones that are genuinely transient. It still shows on the target's page, and a
manual sync retries it regardless.
"""


@dataclasses.dataclass(slots=True)
class SyncOutcome:
    """What one pass over a target actually did."""

    correlation_id: uuid.UUID
    created: int = 0
    adopted: int = 0
    """Accounts that already existed downstream and were linked rather than created.

    Counted separately because the two mean different things to whoever reads the
    result: creating forty accounts is provisioning, adopting forty is onboarding a
    system that already had them."""

    updated: int = 0
    deactivated: int = 0
    reactivated: int = 0
    unchanged: int = 0
    failed: int = 0
    skipped_exhausted: int = 0
    stopped_early: str | None = None

    @property
    def changed(self) -> bool:
        return bool(
            self.created or self.adopted or self.updated or self.deactivated or self.reactivated
        )

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.stopped_early is None

    def as_detail(self) -> dict[str, object]:
        return {
            "created": self.created,
            "adopted": self.adopted,
            "updated": self.updated,
            "deactivated": self.deactivated,
            "reactivated": self.reactivated,
            "unchanged": self.unchanged,
            "failed": self.failed,
            "skipped_exhausted": self.skipped_exhausted,
            "stopped_early": self.stopped_early,
        }


async def entitled_people(db: AsyncSession, target: ProvisioningTarget) -> list[User]:
    """Who should have an account in this target.

    The people with access to its application — directly or through a group — and
    active. This phase adds no new notion of who belongs where: these are the same
    rows P5 reads before it will sign a login.

    Deactivated people are excluded rather than absent, which matters: they will have
    links, and a link with no entitled person behind it is what triggers
    deprovisioning.
    """
    direct = select(AppAssignment.user_id).where(
        AppAssignment.application_id == target.application_id,
        AppAssignment.user_id.is_not(None),
    )
    through_group = (
        select(GroupMember.user_id)
        .join(AppAssignment, AppAssignment.group_id == GroupMember.group_id)
        .where(AppAssignment.application_id == target.application_id)
    )

    rows = await db.scalars(
        select(User)
        .where(
            User.active.is_(True),
            or_(User.id.in_(direct), User.id.in_(through_group)),
        )
        .order_by(User.user_name)
    )
    return list(rows.all())


async def _links_by_user(
    db: AsyncSession, target: ProvisioningTarget
) -> dict[uuid.UUID, ProvisioningLink]:
    rows = await db.scalars(select(ProvisioningLink).where(ProvisioningLink.target_id == target.id))
    return {link.user_id: link for link in rows.all()}


def _payload_for(person: User) -> dict[str, object]:
    """What we tell the downstream about somebody.

    externalId is our own id rather than anything about them, so a downstream can
    match its account back to us even after their name, email or username changes.
    Using an email here is the mistake that makes a marriage look like a new person.
    """
    return user_payload(
        user_name=person.user_name,
        email=person.email,
        display_name=person.display_name,
        given_name=person.given_name,
        family_name=person.family_name,
        department=person.department,
        external_id=str(person.id),
        active=True,
    )


def _needs_push(link: ProvisioningLink, person: User) -> bool:
    """Whether this person has changed since we last pushed them.

    ``updated_at`` against ``last_pushed_at``, which both rows already carry. A row
    touched without a real change gets pushed again, which is the safe direction:
    the cost is one request, and the alternative direction is somebody's details
    silently never arriving.
    """
    if link.state is not LinkState.ACTIVE:
        return True
    if link.last_pushed_at is None:
        return True
    return person.updated_at > link.last_pushed_at


async def _create_or_adopt(client: OutboundScim, person: User) -> tuple[str, str]:
    """Create the account, or take over one that is already there.

    A downstream answering 409 is saying an account with this userName exists and
    we do not know its id. That is not a failure to retry — retrying produces the
    same 409 forever — and it is not fatal either. It is what onboarding a
    downstream that already has people looks like, which is the normal case for
    anything other than an empty system.

    So the id is looked up and the account adopted, then brought into line with what
    we hold. find_user refuses to guess when more than one account matches, and that
    refusal is left to propagate: linking to an account at random is a mistake nobody
    can see afterwards.

    Returns the remote id and the audit action describing what happened.
    """
    payload = _payload_for(person)

    try:
        account = await client.create_user(payload)
        return account.remote_id, "provisioning.account_created"
    except PushFailed as exc:
        if not exc.is_conflict:
            raise

        existing = await client.find_user(person.user_name)
        if existing is None:
            # The downstream said the name was taken and then could not find it.
            # Nothing sensible to do, and inventing a retry would loop.
            raise PushFailed(
                f"the target refused to create {person.user_name} because it already "
                "exists, then could not find it. Its uniqueness rule and its search "
                "disagree.",
                status=exc.status,
            ) from exc

        await client.replace_user(existing.remote_id, payload)
        return existing.remote_id, "provisioning.account_adopted"


async def _record(
    db: AsyncSession,
    *,
    correlation_id: uuid.UUID,
    action: str,
    target: ProvisioningTarget,
    outcome: AuditOutcome,
    person: User | None = None,
    detail: dict[str, object] | None = None,
) -> None:
    """One audit entry, tied to the run that produced it, committed immediately.

    The commit is the important part and it is here rather than at the call sites so
    the rule holds everywhere by construction: nothing this module writes to the
    audit log stays in an open transaction.

    ``append_event`` takes ``pg_advisory_xact_lock`` and holds it until commit,
    because the log is a hash chain and two writers would produce two rows claiming
    the same predecessor. A sync that kept one transaction open for the whole run
    would hold that lock across every HTTP request it makes — so one slow downstream
    would block every audit write in the application, and pointing the sync at our own
    SCIM server deadlocks outright.

    Committing per entry also means a run interrupted halfway leaves the people it
    finished done, instead of rolling all of them back.
    """
    await append_event(
        db,
        AuditDraft(
            action=action,
            # SYSTEM, not the person who triggered it. A sync is our own job acting on
            # decisions other people already made, and attributing forty account
            # creations to whoever clicked the button would misrepresent who decided
            # each one — that is what the assignment's own audit entry is for.
            actor_type=ActorType.SYSTEM,
            actor_label=f"provisioning sync -> {target.application.name}"
            if target.application
            else "provisioning sync",
            outcome=outcome,
            target_type="user" if person else "provisioning_target",
            target_id=str(person.id) if person else str(target.id),
            target_label=person.user_name if person else target.base_url,
            correlation_id=correlation_id,
            detail=detail or {},
        ),
    )
    await db.commit()


def _client_for(target: ProvisioningTarget, settings: Settings) -> OutboundScim:
    """Build the client, decrypting the token at the last moment.

    Decrypted here rather than held on the target object, so the plaintext exists for
    as short a time as possible and never on a model that might get logged.
    """
    return OutboundScim(
        base_url=target.scim_root,
        token=decrypt(target.token_encrypted, settings),
    )


async def reconcile(
    db: AsyncSession,
    target: ProvisioningTarget,
    settings: Settings,
    *,
    now: dt.datetime,
    correlation_id: uuid.UUID | None = None,
    force: bool = False,
) -> SyncOutcome:
    """Make the target's accounts match who is entitled to them.

    Creates what is missing, updates what has changed, deactivates what should no
    longer be there, and revives what has come back. Failures on one person do not
    stop the others.

    Args:
        force: Push everybody regardless of whether they look unchanged, and retry
            links that have exhausted their attempts. What a manual "sync now" means.

    Returns:
        What it did, including the correlation id every audit entry shares.
    """
    run = SyncOutcome(correlation_id=correlation_id or uuid.uuid4())

    if not target.enabled:
        run.stopped_early = "the target is switched off"
        return run

    try:
        client = _client_for(target, settings)
    except CannotDecrypt as exc:
        # Nothing can be pushed and no amount of retrying helps, so this is a target
        # level failure rather than a per-person one.
        run.stopped_early = str(exc)
        target.last_sync_at = now
        target.last_sync_ok = False
        target.last_error = str(exc)
        await _record(
            db,
            correlation_id=run.correlation_id,
            action="provisioning.sync_failed",
            target=target,
            outcome=AuditOutcome.FAILURE,
            detail={"reason": str(exc)},
        )
        return run

    entitled = await entitled_people(db, target)
    links = await _links_by_user(db, target)
    entitled_ids = {person.id for person in entitled}

    await _record(
        db,
        correlation_id=run.correlation_id,
        action="provisioning.sync_started",
        target=target,
        outcome=AuditOutcome.SUCCESS,
        detail={"entitled": len(entitled), "existing_links": len(links), "forced": force},
    )

    # --------------------------------------------------------- who should exist
    for person in entitled:
        link = links.get(person.id)

        if link is None:
            link = ProvisioningLink(target_id=target.id, user_id=person.id)
            db.add(link)
            await db.flush()
            links[person.id] = link

        if link.attempts >= MAX_ATTEMPTS and not force:
            # Left alone rather than retried. Still visible on the target's page, and
            # a manual sync picks it up.
            run.skipped_exhausted += 1
            continue

        if not force and not _needs_push(link, person):
            run.unchanged += 1
            continue

        # Nothing open while we talk to somebody else's server. The audit chain lock
        # is transaction scoped, so any transaction still open here would hold it for
        # the length of a network round trip — and against our own SCIM server, which
        # is what the tests point at, that deadlocks outright.
        await db.commit()

        try:
            if link.exists_downstream:
                if link.state is LinkState.DEPROVISIONED:
                    # A rehire. Reactivating revives the account and everything
                    # attached to it, where creating a second one would not.
                    await client.set_active(link.remote_id or "", active=True)
                    run.reactivated += 1
                    action = "provisioning.account_reactivated"
                else:
                    await client.replace_user(link.remote_id or "", _payload_for(person))
                    run.updated += 1
                    action = "provisioning.account_updated"
            else:
                remote_id, action = await _create_or_adopt(client, person)
                link.remote_id = remote_id
                if action == "provisioning.account_adopted":
                    run.adopted += 1
                else:
                    run.created += 1

            link.state = LinkState.ACTIVE
            link.last_pushed_at = now
            link.last_error = None
            link.attempts = 0

            await _record(
                db,
                correlation_id=run.correlation_id,
                action=action,
                target=target,
                outcome=AuditOutcome.SUCCESS,
                person=person,
                detail={"remote_id": link.remote_id},
            )

        except PushFailed as exc:
            link.state = LinkState.FAILED
            link.last_error = str(exc)
            link.attempts += 1
            run.failed += 1

            await _record(
                db,
                correlation_id=run.correlation_id,
                action="provisioning.push_failed",
                target=target,
                outcome=AuditOutcome.FAILURE,
                person=person,
                detail={
                    "error": str(exc),
                    "status": exc.status,
                    "attempts": link.attempts,
                    "account_exists": link.exists_downstream,
                },
            )

            if exc.is_authentication:
                # Everything after this fails the same way. Stopping is kinder to the
                # far end and much clearer in the log than a thousand identical rows.
                run.stopped_early = (
                    "the target rejected our token, so the rest of the run was "
                    "abandoned rather than repeating the same failure"
                )
                break

    # ------------------------------------------------- who should not exist
    if run.stopped_early is None:
        for user_id, link in links.items():
            if user_id in entitled_ids:
                continue
            if link.state in (LinkState.DEPROVISIONED, LinkState.PENDING):
                continue
            if not link.exists_downstream:
                # Nothing out there to switch off. Recorded as deprovisioned so it
                # stops being considered every run.
                link.state = LinkState.DEPROVISIONED
                continue

            leaver = await db.get(User, user_id)
            await db.commit()

            try:
                await client.set_active(link.remote_id or "", active=False)
                link.state = LinkState.DEPROVISIONED
                link.last_pushed_at = now
                link.last_error = None
                link.attempts = 0
                run.deactivated += 1

                await _record(
                    db,
                    correlation_id=run.correlation_id,
                    action="provisioning.account_deactivated",
                    target=target,
                    outcome=AuditOutcome.SUCCESS,
                    person=leaver,
                    detail={
                        "remote_id": link.remote_id,
                        # Why they lost it, which is the question asked afterwards.
                        "reason": "no longer has access to this application",
                    },
                )

            except PushFailed as exc:
                # ORPHANED rather than FAILED, and the distinction is the point: we
                # were told to remove somebody's access and could not. They still have
                # it. That is the finding an access review has to surface.
                link.state = LinkState.ORPHANED
                link.last_error = str(exc)
                link.attempts += 1
                run.failed += 1

                await _record(
                    db,
                    correlation_id=run.correlation_id,
                    action="provisioning.deprovision_failed",
                    target=target,
                    outcome=AuditOutcome.FAILURE,
                    person=leaver,
                    detail={
                        "error": str(exc),
                        "status": exc.status,
                        "consequence": ("they still have access to this application downstream"),
                    },
                )

                if exc.is_authentication:
                    run.stopped_early = "the target rejected our token"
                    break

    target.last_sync_at = now
    target.last_sync_ok = run.ok
    target.last_error = run.stopped_early if not run.ok else None

    await _record(
        db,
        correlation_id=run.correlation_id,
        action="provisioning.sync_finished",
        target=target,
        outcome=AuditOutcome.SUCCESS if run.ok else AuditOutcome.FAILURE,
        detail=run.as_detail(),
    )

    logger.info(
        "provisioning.sync_finished",
        extra={
            "target": target.base_url,
            "correlation_id": str(run.correlation_id),
            # Nested rather than splatted. LogRecord already has a `created`
            # attribute — the timestamp — and logging raises KeyError rather than
            # letting `extra` shadow it. as_detail() has a `created` count, so
            # splatting it here failed every single sync.
            "outcome": run.as_detail(),
        },
    )
    return run


async def push_one(
    db: AsyncSession,
    target: ProvisioningTarget,
    person: User,
    settings: Settings,
    *,
    now: dt.datetime,
    correlation_id: uuid.UUID | None = None,
) -> bool:
    """Push one person immediately, without a full pass.

    For reacting to a change as it happens — somebody granted access should get an
    account now, not at the next sync. An optimisation over reconcile rather than a
    replacement: if this fails or is never called, the next reconcile still converges,
    which is exactly the property a change-driven design on its own would not have.

    Returns whether it worked.
    """
    if not target.enabled:
        return False

    link = await db.scalar(
        select(ProvisioningLink).where(
            ProvisioningLink.target_id == target.id,
            ProvisioningLink.user_id == person.id,
        )
    )
    if link is None:
        link = ProvisioningLink(target_id=target.id, user_id=person.id)
        db.add(link)
        await db.flush()

    run_id = correlation_id or uuid.uuid4()

    # Same rule as reconcile: nothing open across the request.
    await db.commit()

    try:
        client = _client_for(target, settings)

        if not person.active:
            if not link.exists_downstream:
                link.state = LinkState.DEPROVISIONED
                return True
            await client.set_active(link.remote_id or "", active=False)
            link.state = LinkState.DEPROVISIONED
            action = "provisioning.account_deactivated"
        elif link.exists_downstream:
            if link.state is LinkState.DEPROVISIONED:
                await client.set_active(link.remote_id or "", active=True)
                action = "provisioning.account_reactivated"
            else:
                await client.replace_user(link.remote_id or "", _payload_for(person))
                action = "provisioning.account_updated"
            link.state = LinkState.ACTIVE
        else:
            remote_id, action = await _create_or_adopt(client, person)
            link.remote_id = remote_id
            link.state = LinkState.ACTIVE

        link.last_pushed_at = now
        link.last_error = None
        link.attempts = 0

        await _record(
            db,
            correlation_id=run_id,
            action=action,
            target=target,
            outcome=AuditOutcome.SUCCESS,
            person=person,
            detail={"remote_id": link.remote_id, "immediate": True},
        )
        return True

    except (PushFailed, CannotDecrypt) as exc:
        link.state = LinkState.FAILED if person.active else LinkState.ORPHANED
        link.last_error = str(exc)
        link.attempts += 1

        await _record(
            db,
            correlation_id=run_id,
            action="provisioning.push_failed",
            target=target,
            outcome=AuditOutcome.FAILURE,
            person=person,
            detail={
                "error": str(exc),
                "immediate": True,
                # The reassurance that matters: this is not lost.
                "note": "the next full sync will try again",
            },
        )
        return False
