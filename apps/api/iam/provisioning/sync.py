"""Deciding what to push, and pushing it.

The client makes requests. This module decides which requests to make.

A few things worth knowing about how this works:

- `reconcile` computes the whole set of accounts a target should have and
  makes it so, rather than taking a list of changes. A change-driven pusher
  gets the leaver case wrong the first time a message is lost or a process
  restarts mid-run, so this recomputes the full answer each time. `push_one`
  still exists on top of that for pushing one person right away, but it's an
  optimization over reconcile, not a replacement - if it's never called, the
  next reconcile still catches up.
- Staleness is `user.updated_at > link.last_pushed_at`, using columns both
  tables already have, instead of hashing the last payload. A row touched
  with no real change still gets re-pushed, which is the safe direction to
  be wrong in.
- Every audit entry a run produces shares one `correlation_id`, so a sync
  that creates forty accounts and fails on three shows up as one event
  instead of forty-three unrelated rows.
- Every audit entry is committed as soon as it's written, so no database
  lock is held while an HTTP call is in flight. `append_event` holds
  `pg_advisory_xact_lock` until commit (the audit log is a hash chain), so
  keeping one transaction open for a whole run would hold that lock across
  every downstream request - and pointing the sync at our own SCIM server
  would deadlock. The commit lives inside `_record` so this holds by
  construction; there's also a commit right before each push so nothing else
  is holding a transaction open either. A side benefit: a run interrupted
  halfway leaves the people it finished done, instead of rolling them back.
- A downstream rejecting one person doesn't stop the run - the rest still get
  processed. An authentication failure does stop the run immediately, since
  the token is wrong and every remaining push would fail the same way.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import or_, select, update
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

A link failing five times in a row is failing for a reason a retry won't
fix, and retrying it every run buries the failures that are actually
transient. It still shows on the target's page, and a manual sync retries it
regardless.
"""


@dataclasses.dataclass(slots=True)
class SyncOutcome:
    """What one pass over a target actually did."""

    correlation_id: uuid.UUID
    created: int = 0
    adopted: int = 0
    """Accounts that already existed downstream and were linked rather than created.

    Counted separately because they mean different things: creating forty
    accounts is provisioning, adopting forty is onboarding a system that
    already had them."""

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
    def touched(self) -> int:
        """How many accounts this pass actually moved.

        Distinct from `changed`, which is a yes-or-no. Summing `changed`
        across targets would count targets, not accounts - showing "1
        pushed" when forty people were provisioned.
        """
        return self.created + self.adopted + self.updated + self.deactivated + self.reactivated

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

    Active people with access to its application, directly or through a
    group - the same rows used to decide whether a login gets signed.

    Deactivated people are excluded here, not just absent: they still have
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


SWEEP_LEASE = dt.timedelta(minutes=15)
"""How long a sync holds its target before another one may take over.

Longer than any sync should take (a first run against 1,200 accounts takes
about forty seconds), and short enough that a worker killed mid-sweep
doesn't wedge the target for an afternoon. Nothing renews it: a sync that
somehow runs longer than this loses its claim, but the worst case is just
one overlap.
"""


class AlreadyRunning(Exception):
    """Another sync holds this target, so this one should not start.

    Not really an error - the sweep just skips and tries again in five
    minutes, and the console tells whoever pressed the button to wait. Both
    beat two reconciles working the same links.
    """


async def take_lease(db: AsyncSession, target: ProvisioningTarget, *, now: dt.datetime) -> None:
    """Claim this target, or refuse to run.

    Uses one conditional UPDATE so the database decides who wins - the loser
    sees zero rows affected rather than a stale read. Two workers issuing
    this at the same instant can't both succeed.

    Raises:
        AlreadyRunning: Somebody else holds an unexpired lease.
    """
    claimed = await db.execute(
        update(ProvisioningTarget)
        .where(
            ProvisioningTarget.id == target.id,
            or_(
                ProvisioningTarget.sweep_lease_until.is_(None),
                ProvisioningTarget.sweep_lease_until < now,
            ),
        )
        .values(sweep_lease_until=now + SWEEP_LEASE)
    )
    await db.commit()

    if claimed.rowcount != 1:
        raise AlreadyRunning(
            f"a sync is already running against {target.base_url}. It will finish, or "
            "its claim expires within fifteen minutes."
        )


async def release_lease(db: AsyncSession, target_id: uuid.UUID) -> None:
    """Give the target back, so the next sync need not wait for the lease to expire.

    Best effort. If this never runs (process killed, database went away),
    the lease just expires on its own - that's why it's a lease and not a flag.
    """
    await db.execute(
        update(ProvisioningTarget)
        .where(ProvisioningTarget.id == target_id)
        .values(sweep_lease_until=None)
    )
    await db.commit()


async def count_waiting(db: AsyncSession, target: ProvisioningTarget) -> int:
    """How many people a sync would touch if it ran right now.

    This exists because the target summary could otherwise say "in step"
    while a leaver sat unpushed - the link *states* (active, failed,
    orphaned) don't answer "has anything changed since we last pushed". With
    no background worker, nothing pushes on its own, so this needs to be
    checked directly rather than inferred from the last run's outcome.

    Built from the same two pieces reconcile() uses (entitled_people and
    _needs_push) rather than a separate approximate query, so it can't drift
    out of sync with what reconcile would actually do. Costs one pass over
    the entitled people, same as a sync's read phase.
    """
    people = await entitled_people(db, target)
    links = await _links_by_user(db, target)

    waiting = 0
    entitled: set[uuid.UUID] = set()

    for person in people:
        entitled.add(person.id)
        link = links.get(person.id)
        if link is None or not link.exists_downstream or _needs_push(link, person):
            waiting += 1

    # The other direction: somebody with a live account downstream who is no
    # longer entitled. This is the case this count exists to catch.
    for user_id, link in links.items():
        if user_id not in entitled and link.state is LinkState.ACTIVE:
            waiting += 1

    return waiting


async def _links_by_user(
    db: AsyncSession, target: ProvisioningTarget
) -> dict[uuid.UUID, ProvisioningLink]:
    rows = await db.scalars(select(ProvisioningLink).where(ProvisioningLink.target_id == target.id))
    return {link.user_id: link for link in rows.all()}


def _payload_for(person: User) -> dict[str, object]:
    """What we tell the downstream about somebody.

    externalId is our own id, not anything about them, so a downstream can
    match its account back to us even after their name, email, or username
    changes. Using email here would make something like a marriage/name
    change look like a new person.
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

    Compares `updated_at` against `last_pushed_at`, which both rows already
    carry. A row touched without a real change gets pushed again - wasteful
    but safe, versus the alternative of details silently never arriving.

    Note: the two timestamps come from different clocks. `updated_at` is
    stamped by Postgres via `func.now()`, while `last_pushed_at` is whatever
    the caller passed to reconcile(). If the API's clock runs behind the
    database's, everybody looks stale on every pass and a full sync re-pushes
    the whole directory (about 1,200 requests / forty seconds against the
    seeded data). Still correct, just wasteful - but a fixed literal here
    would be worse, as the test fixture found out the hard way.
    """
    if link.state is not LinkState.ACTIVE:
        return True
    if link.last_pushed_at is None:
        return True
    return person.updated_at > link.last_pushed_at


async def _create_or_adopt(client: OutboundScim, person: User) -> tuple[str, str]:
    """Create the account, or take over one that is already there.

    A 409 means an account with this userName already exists and we don't
    know its id - not a failure to retry (that would just repeat the 409
    forever), and not fatal. It's what onboarding a downstream that already
    has people looks like.

    So we look up the id, adopt the account, and bring it into line with what
    we hold. find_user refuses to guess when more than one account matches;
    that exception is left to propagate rather than picking one at random.

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
            # The downstream said the name was taken, then couldn't find it.
            # Nothing sensible to do here, and retrying would just loop.
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

    The commit lives here, not at the call sites, so nothing this module
    writes to the audit log stays in an open transaction.

    `append_event` holds `pg_advisory_xact_lock` until commit, since the log
    is a hash chain and two writers would otherwise produce two rows
    claiming the same predecessor. Keeping one transaction open for a whole
    run would hold that lock across every HTTP request - one slow downstream
    would block every audit write in the app, and pointing the sync at our
    own SCIM server would deadlock outright.

    Committing per entry also means a run interrupted halfway leaves the
    people it finished done, instead of rolling all of them back.
    """
    await append_event(
        db,
        AuditDraft(
            action=action,
            # SYSTEM, not the person who triggered it. A sync acts on
            # decisions other people already made; the assignment's own
            # audit entry is what records who actually decided.
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

    Decrypted here rather than held on the target object, so the plaintext
    exists as briefly as possible and never sits on a model that might get
    logged.
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

    Creates what is missing, updates what has changed, deactivates what
    should no longer be there, and revives what has come back. Failures on
    one person do not stop the others.

    Args:
        force: Push everybody regardless of whether they look unchanged, and retry
            links that have exhausted their attempts. What a manual "sync now" means.

    Takes a lease on the target first, so two syncs can't work the same
    links - covers both two worker machines and someone pressing "sync now"
    while a sweep is already running.

    Returns:
        What it did, including the correlation id every audit entry shares.

    Raises:
        AlreadyRunning: Another sync holds this target.
    """
    await take_lease(db, target, now=now)
    try:
        return await _reconcile_holding_lease(
            db, target, settings, now=now, correlation_id=correlation_id, force=force
        )
    finally:
        # Best effort - if this never runs, the lease just expires on its own.
        await release_lease(db, target.id)


async def _reconcile_holding_lease(
    db: AsyncSession,
    target: ProvisioningTarget,
    settings: Settings,
    *,
    now: dt.datetime,
    correlation_id: uuid.UUID | None = None,
    force: bool = False,
) -> SyncOutcome:
    """The work itself, with the target already claimed.

    Split out so the lease handling in reconcile() stays a few lines and
    this function keeps the shape it had before the lease existed.
    """
    run = SyncOutcome(correlation_id=correlation_id or uuid.uuid4())

    if not target.enabled:
        run.stopped_early = "the target is switched off"
        return run

    try:
        client = _client_for(target, settings)
    except CannotDecrypt as exc:
        # Nothing can be pushed and retrying won't help - this is a
        # target-level failure, not a per-person one.
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
            # Left alone rather than retried. Still visible on the target's
            # page, and a manual sync picks it up.
            run.skipped_exhausted += 1
            continue

        if not force and not _needs_push(link, person):
            run.unchanged += 1
            continue

        # Nothing open while we talk to somebody else's server - an open
        # transaction here would hold the audit chain lock for the length of
        # a network round trip, and against our own SCIM server (what the
        # tests point at) that deadlocks outright.
        await db.commit()

        try:
            if link.exists_downstream:
                if link.state is LinkState.DEPROVISIONED:
                    # A rehire. Reactivating revives the account and
                    # everything attached to it; creating a new one wouldn't.
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
                # Everything after this fails the same way, so stop instead
                # of logging a thousand identical rows.
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
                # Nothing out there to switch off. Mark deprovisioned so it
                # stops being considered on future runs.
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
                        "reason": "no longer has access to this application",
                    },
                )

            except PushFailed as exc:
                # ORPHANED, not FAILED: we were told to remove access and
                # couldn't, so they still have it. That's what an access
                # review needs to surface.
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
            # Nested, not splatted. LogRecord already has a `created`
            # attribute (the timestamp), and logging raises KeyError instead
            # of letting `extra` shadow it. as_detail() has its own `created`
            # count, so splatting it here failed every single sync.
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

    For reacting to a change as it happens - somebody granted access should
    get an account now, not at the next sync. An optimization over reconcile,
    not a replacement: if this fails or is never called, the next reconcile
    still catches up.

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

    # Same rule as reconcile: nothing open while the request is in flight.
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
                "note": "the next full sync will try again",
            },
        )
        return False
