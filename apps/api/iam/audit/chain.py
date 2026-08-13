"""Audit log that shows when someone has edited it.

Every entry stores a fingerprint (a SHA-256 hash) of the entry before it. If
anyone edits, deletes, or inserts an old entry, its fingerprint stops matching
what the next entry expects, and the verify check tells you which entry broke.

One limit worth being clear about: this catches tampering, it doesn't prevent it.
Someone with write access to the database could redo all the fingerprints after
their edit. Blocking that properly needs a copy of the fingerprints kept
somewhere we don't control, and we're not doing that. What this does catch is a
stray UPDATE or a bug in our own code, and the database rule that blocks edits
covers the rest.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import GENESIS_HASH, AuditEvent
from iam.models.enums import ActorType, AuditOutcome

AUDIT_CHAIN_LOCK_KEY = 728_193_745
"""Lock key used to stop two writes happening at once. See append_event."""

VERIFY_BATCH_SIZE = 1_000
"""How many rows to read at a time when verifying, so we don't load 45k at once."""


@dataclass(frozen=True, slots=True)
class AuditDraft:
    """An entry waiting to be written. Frozen so nothing can change it halfway."""

    action: str
    actor_type: ActorType
    actor_label: str
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    actor_id: uuid.UUID | None = None
    target_type: str | None = None
    target_id: str | None = None
    target_label: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    correlation_id: uuid.UUID | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    occurred_at: dt.datetime | None = None


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """What the verify check found."""

    valid: bool
    events_checked: int
    broken_at_id: int | None = None
    reason: str | None = None


def canonical_form(
    *,
    occurred_at: dt.datetime,
    actor_type: str,
    actor_id: uuid.UUID | None,
    actor_label: str,
    action: str,
    outcome: str,
    target_type: str | None,
    target_id: str | None,
    target_label: str | None,
    ip_address: str | None,
    user_agent: str | None,
    correlation_id: uuid.UUID | None,
    detail: dict[str, Any],
) -> str:
    """Turn an entry into a text string, always the same way.

    The same entry has to produce the exact same text on any machine, any Python
    version, and after being saved to Postgres and read back. That's why the keys
    are sorted, the spacing is fixed, times are forced to UTC, and ensure_ascii is
    on. Change any of that and every existing fingerprint stops matching.
    """
    payload = {
        "occurred_at": occurred_at.astimezone(dt.UTC).isoformat(),
        "actor_type": actor_type,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_label": actor_label,
        "action": action,
        "outcome": outcome,
        "target_type": target_type,
        "target_id": target_id,
        "target_label": target_label,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "correlation_id": str(correlation_id) if correlation_id else None,
        "detail": detail,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def compute_hash(prev_hash: str, canonical: str) -> str:
    """Fingerprint one entry. The \\x1f between the two parts keeps them separate
    so different splits can't produce the same input."""
    return hashlib.sha256(f"{prev_hash}\x1f{canonical}".encode()).hexdigest()


def hash_for_event(event: AuditEvent) -> str:
    """Work out what fingerprint a saved row should have, so we can compare."""
    return compute_hash(
        event.prev_hash,
        canonical_form(
            occurred_at=event.occurred_at,
            actor_type=str(event.actor_type),
            actor_id=event.actor_id,
            actor_label=event.actor_label,
            action=event.action,
            outcome=str(event.outcome),
            target_type=event.target_type,
            target_id=event.target_id,
            target_label=event.target_label,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            correlation_id=event.correlation_id,
            detail=event.detail,
        ),
    )


async def append_event(session: AsyncSession, draft: AuditDraft) -> AuditEvent:
    """Add one entry to the end of the log.

    We read the last entry, then write a new one pointing at it. If two requests
    did that at the same time, both would point at the same last entry and one
    would end up orphaned. The lock below stops that. It's tied to the
    transaction, so Postgres releases it on commit or rollback and there's no
    cleanup to forget.

    This doesn't commit. The caller does, so the log entry and the change it
    describes go in together. If the change fails, the log entry disappears with
    it and we never claim something happened that didn't.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": AUDIT_CHAIN_LOCK_KEY},
    )

    tail_hash = await session.scalar(
        select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)
    )
    prev_hash = tail_hash or GENESIS_HASH

    # Set here, not by the database default, because the timestamp goes into the
    # fingerprint and we need to know it before writing the row.
    occurred_at = draft.occurred_at or dt.datetime.now(dt.UTC)

    canonical = canonical_form(
        occurred_at=occurred_at,
        actor_type=str(draft.actor_type),
        actor_id=draft.actor_id,
        actor_label=draft.actor_label,
        action=draft.action,
        outcome=str(draft.outcome),
        target_type=draft.target_type,
        target_id=draft.target_id,
        target_label=draft.target_label,
        ip_address=draft.ip_address,
        user_agent=draft.user_agent,
        correlation_id=draft.correlation_id,
        detail=draft.detail,
    )

    event = AuditEvent(
        occurred_at=occurred_at,
        actor_type=draft.actor_type,
        actor_id=draft.actor_id,
        actor_label=draft.actor_label,
        action=draft.action,
        outcome=draft.outcome,
        target_type=draft.target_type,
        target_id=draft.target_id,
        target_label=draft.target_label,
        ip_address=draft.ip_address,
        user_agent=draft.user_agent,
        correlation_id=draft.correlation_id,
        detail=draft.detail,
        prev_hash=prev_hash,
        hash=compute_hash(prev_hash, canonical),
    )
    session.add(event)
    await session.flush()
    return event


async def verify_chain(session: AsyncSession, *, limit: int | None = None) -> ChainVerification:
    """Check the log from the start and report the first entry that doesn't add up.

    Reads in batches so a big log doesn't have to fit in memory.

    Args:
        session: Database session.
        limit: Stop after this many entries. None checks everything.
    """
    expected_prev = GENESIS_HASH
    checked = 0
    last_id = 0

    while True:
        remaining = None if limit is None else limit - checked
        if remaining is not None and remaining <= 0:
            break

        batch_size = VERIFY_BATCH_SIZE if remaining is None else min(VERIFY_BATCH_SIZE, remaining)
        rows = (
            await session.scalars(
                select(AuditEvent)
                .where(AuditEvent.id > last_id)
                .order_by(AuditEvent.id)
                .limit(batch_size)
            )
        ).all()

        if not rows:
            break

        for event in rows:
            if event.prev_hash != expected_prev:
                return ChainVerification(
                    valid=False,
                    events_checked=checked,
                    broken_at_id=event.id,
                    reason=(
                        "this entry points at a fingerprint that doesn't match the "
                        "entry before it, so something earlier was changed or removed"
                    ),
                )

            recomputed = hash_for_event(event)
            if recomputed != event.hash:
                return ChainVerification(
                    valid=False,
                    events_checked=checked,
                    broken_at_id=event.id,
                    reason="the saved fingerprint doesn't match this entry's contents",
                )

            expected_prev = event.hash
            checked += 1
            last_id = event.id

    return ChainVerification(valid=True, events_checked=checked)
