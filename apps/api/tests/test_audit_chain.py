"""Tests for the audit log: fingerprints, linking, tamper detection, add-only.

The first half runs anywhere. The second half needs a real Postgres, because the
things it checks live in the database — the lock that stops two writes at once,
and the rules that reject UPDATE and DELETE. Faking those would prove nothing.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit import AuditDraft, append_event, canonical_form, compute_hash, verify_chain
from iam.models.audit import GENESIS_HASH, AuditEvent
from iam.models.enums import ActorType, AuditOutcome

FIXED_TIME = dt.datetime(2026, 8, 13, 12, 0, 0, tzinfo=dt.UTC)
ACTOR_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
TARGET_ID = "22222222-2222-4222-8222-222222222222"
DEFAULT_DETAIL: dict[str, Any] = {"changed": {"department": {"from": "Sales", "to": "Finance"}}}


def canonical(
    *,
    occurred_at: dt.datetime = FIXED_TIME,
    actor_type: str = "user",
    actor_id: uuid.UUID | None = ACTOR_ID,
    actor_label: str = "Ada Lovelace <ada@demo.local>",
    action: str = "user.updated",
    outcome: str = "success",
    target_type: str | None = "user",
    target_id: str | None = TARGET_ID,
    target_label: str | None = "grace@demo.local",
    ip_address: str | None = "10.0.0.1",
    user_agent: str | None = "pytest",
    correlation_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> str:
    """canonical_form with sensible defaults, so a test can change one field."""
    return canonical_form(
        occurred_at=occurred_at,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_label=actor_label,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        ip_address=ip_address,
        user_agent=user_agent,
        correlation_id=correlation_id,
        detail=DEFAULT_DETAIL if detail is None else detail,
    )


# --------------------------------------------------------------------- unit


def test_canonical_form_is_stable() -> None:
    """Same input, same output. Everything else here relies on that."""
    assert canonical() == canonical()


def test_canonical_form_normalises_timezone() -> None:
    """The same moment written in a different timezone must come out the same.

    If it didn't, a database handing timestamps back in its own timezone would make
    entries fail the check on a server set up differently from the one that wrote
    them.
    """
    kolkata = dt.timezone(dt.timedelta(hours=5, minutes=30))
    assert canonical(occurred_at=FIXED_TIME.astimezone(kolkata)) == canonical()


def test_canonical_form_is_insensitive_to_detail_key_order() -> None:
    """Postgres doesn't keep JSON keys in order, so the fingerprint can't care."""
    assert canonical(detail={"a": 1, "b": 2}) == canonical(detail={"b": 2, "a": 1})


# One entry per field that goes into the fingerprint, and a change to it. A field
# missing from both this list and the fingerprint could be edited without anything
# noticing, which is the gap these tests close.
MUTATIONS: tuple[tuple[str, Callable[[], str]], ...] = (
    ("occurred_at", lambda: canonical(occurred_at=FIXED_TIME + dt.timedelta(seconds=1))),
    ("actor_type", lambda: canonical(actor_type="idp")),
    ("actor_id", lambda: canonical(actor_id=None)),
    ("actor_label", lambda: canonical(actor_label="Someone Else <else@demo.local>")),
    ("action", lambda: canonical(action="user.deleted")),
    ("outcome", lambda: canonical(outcome="denied")),
    ("target_type", lambda: canonical(target_type="group")),
    ("target_id", lambda: canonical(target_id="33333333-3333-4333-8333-333333333333")),
    ("target_label", lambda: canonical(target_label="someone.else@demo.local")),
    ("ip_address", lambda: canonical(ip_address="10.0.0.2")),
    ("user_agent", lambda: canonical(user_agent="curl/8.0")),
    ("correlation_id", lambda: canonical(correlation_id=ACTOR_ID)),
    ("detail", lambda: canonical(detail={"changed": {}})),
)


@pytest.mark.parametrize(("field", "mutate"), MUTATIONS, ids=[name for name, _ in MUTATIONS])
def test_changing_any_hashed_field_changes_the_hash(field: str, mutate: Callable[[], str]) -> None:
    baseline = compute_hash(GENESIS_HASH, canonical())
    assert compute_hash(GENESIS_HASH, mutate()) != baseline, f"{field} is not hashed"


def test_hash_depends_on_the_predecessor() -> None:
    """The same content in a different position gets a different fingerprint.

    That's what stops someone copying a real entry into another spot in the log.
    """
    content = canonical()
    assert compute_hash(GENESIS_HASH, content) != compute_hash("a" * 64, content)


def test_hash_is_a_sha256_hex_digest() -> None:
    digest = compute_hash(GENESIS_HASH, canonical())
    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)


# -------------------------------------------------------------- integration


def _draft(action: str) -> AuditDraft:
    return AuditDraft(
        action=action,
        actor_type=ActorType.SYSTEM,
        actor_label="pytest",
        outcome=AuditOutcome.SUCCESS,
        detail={"test": True},
    )


@pytest.mark.integration
async def test_append_links_to_the_previous_event(db_session: AsyncSession) -> None:
    """Each new entry records the fingerprint of the one before it."""
    first = await append_event(db_session, _draft("test.first"))
    second = await append_event(db_session, _draft("test.second"))

    assert second.prev_hash == first.hash
    assert second.id > first.id


@pytest.mark.integration
async def test_chain_verifies_after_appending(db_session: AsyncSession) -> None:
    for index in range(5):
        await append_event(db_session, _draft(f"test.event{index}"))

    result = await verify_chain(db_session)

    assert result.valid, result.reason
    assert result.events_checked >= 5


@pytest.mark.integration
async def test_tampering_is_detected_at_the_altered_event(db_session: AsyncSession) -> None:
    """Change a saved entry and the check must fail, naming that entry.

    We have to switch the database rule off just to make the edit, which is the
    interesting bit: even with that protection gone, the fingerprints still catch
    it.
    """
    target = await append_event(db_session, _draft("test.tamper_me"))
    await append_event(db_session, _draft("test.after"))
    await db_session.flush()

    await db_session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
    await db_session.execute(
        text("UPDATE audit_events SET actor_label = :label WHERE id = :id"),
        {"label": "Someone Else", "id": target.id},
    )
    await db_session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))
    db_session.expunge_all()

    result = await verify_chain(db_session)

    assert not result.valid
    assert result.broken_at_id == target.id
    assert result.reason is not None and "contents" in result.reason


@pytest.mark.integration
async def test_database_blocks_updates(db_session: AsyncSession) -> None:
    """Postgres itself refuses this, not just our code."""
    event = await append_event(db_session, _draft("test.no_update"))
    await db_session.flush()

    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(
            text("UPDATE audit_events SET action = 'hacked' WHERE id = :id"),
            {"id": event.id},
        )


@pytest.mark.integration
async def test_database_blocks_deletes(db_session: AsyncSession) -> None:
    event = await append_event(db_session, _draft("test.no_delete"))
    await db_session.flush()

    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": event.id})


@pytest.mark.integration
async def test_stored_event_round_trips_through_postgres(db_session: AsyncSession) -> None:
    """An entry read back from the database still matches its fingerprint.

    Catches the case where saving and loading changes something subtly — timestamp
    precision, JSON key order — so entries pass the check in memory but fail once
    they've been through Postgres.
    """
    appended = await append_event(
        db_session,
        AuditDraft(
            action="test.round_trip",
            actor_type=ActorType.IDP,
            actor_label="Upstream IdP <authentik>",
            correlation_id=uuid.uuid4(),
            detail={"zebra": 1, "alpha": {"nested": [1, 2, 3]}},
            ip_address="2001:db8::1",
        ),
    )
    await db_session.flush()
    db_session.expunge_all()

    reloaded = await db_session.scalar(select(AuditEvent).where(AuditEvent.id == appended.id))
    assert reloaded is not None

    from iam.audit import hash_for_event

    assert hash_for_event(reloaded) == reloaded.hash
