"""The background sweep: pushing changes without somebody pressing a button.

Why this exists
---------------

Provisioning ran only inside the request that asked for it, so nothing reached a
downstream system until a person opened the console and pressed Sync now. That was
stated honestly rather than hidden — the target panel says "changes waiting" and the
runbook listed it — but it makes the leaver flow depend on somebody remembering.

The gap is not theoretical. It has already happened here: Okta deactivated somebody
at 8:51:40, the last sync had run at 8:51:12, and their account stayed live in the
HRMS until a person noticed. Twenty-eight seconds of bad luck and a leaver keeps
their access indefinitely.

Why a sweep rather than a queue
-------------------------------

Because reconcile() is a reconciler, not a reaction. It asks "who should have an
account here, and what does this system currently have" and fixes the difference —
so running it on a timer converges on the right answer no matter what happened in
between, including changes this process never saw.

A queue would be the natural choice for a system that reacts to events, and it would
be worse here for exactly that reason: a dropped message means a person keeps access
forever, and nothing notices. A missed sweep means the next one does the work. The
failure modes are not comparable.

It is also less machinery. No broker, no dead-letter handling, no ordering
questions, no second thing to run — which matters more than elegance for a
deployment that is two small machines.

What it deliberately does not do
--------------------------------

It does not force. A forced run retries links that have failed their attempt limit,
and doing that every few minutes turns a permanently broken target into a permanent
source of load and log noise. Somebody pressing Sync now can force; a timer should
not.

It does not run more than one sweep at a time. Two overlapping reconciles against the
same target would race on the same links, and the second would mostly do nothing
useful while holding a connection open.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from iam.config import Settings, get_settings
from iam.db import build_engine, build_sessionmaker
from iam.logging_setup import configure_logging
from iam.models.provisioning import ProvisioningTarget
from iam.provisioning import reconcile

logger = logging.getLogger(__name__)


async def sweep_once(
    sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    now: dt.datetime,
) -> dict[str, int]:
    """Reconcile every enabled target, once.

    Each target gets its own session and its own correlation id, so one target's
    failure cannot roll back another's work and the audit entries for a run can be
    read back as one story.

    Returns a small summary for the log line, and for the tests to assert on rather
    than reaching into the audit table.
    """
    async with sessionmaker() as session:
        targets = list(
            await session.scalars(
                select(ProvisioningTarget)
                .where(ProvisioningTarget.enabled.is_(True))
                # The application is read while building audit entries, and a lazy
                # load there is the MissingGreenlet this codebase has hit three
                # times. Eager, deliberately.
                .options(selectinload(ProvisioningTarget.application))
            )
        )

    summary = {"targets": len(targets), "pushed": 0, "failed": 0}

    for target in targets:
        correlation_id = uuid.uuid4()
        try:
            async with sessionmaker() as session:
                fresh = await session.get(
                    ProvisioningTarget,
                    target.id,
                    options=[selectinload(ProvisioningTarget.application)],
                )
                if fresh is None or not fresh.enabled:
                    # Removed or paused between the listing and now. Ordinary.
                    continue

                outcome = await reconcile(
                    session, fresh, settings, now=now, correlation_id=correlation_id
                )

            summary["pushed"] += outcome.touched
            summary["failed"] += outcome.failed
            if outcome.changed or outcome.failed:
                logger.info(
                    "worker.target_swept",
                    extra={
                        "target": fresh.base_url,
                        "correlation_id": str(correlation_id),
                        "outcome": outcome.as_detail(),
                    },
                )
        except Exception:
            # One target must not stop the others. A downstream that is down, a
            # token that has been rotated at the far end, a certificate that
            # expired — all of them are somebody else's outage, and the remaining
            # targets are still ours to keep in step.
            summary["failed"] += 1
            logger.exception(
                "worker.target_failed",
                extra={"target": target.base_url, "correlation_id": str(correlation_id)},
            )

    return summary


async def run_forever(settings: Settings | None = None) -> None:
    """Sweep, wait, sweep again, until something stops the process.

    The interval is a floor rather than a schedule: a sweep that takes longer than
    the interval simply delays the next one, which is what you want. Trying to keep
    to a fixed cadence would start a second sweep on top of a slow one.
    """
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    engine = build_engine(resolved)
    sessionmaker = build_sessionmaker(engine)

    interval = dt.timedelta(seconds=resolved.provisioning_sweep_seconds)
    logger.info(
        "worker.started",
        extra={"every_seconds": interval.total_seconds(), "env": resolved.app_env},
    )

    try:
        while True:
            started = dt.datetime.now(dt.UTC)
            try:
                summary = await sweep_once(sessionmaker, resolved, now=started)
                if summary["pushed"] or summary["failed"]:
                    logger.info("worker.sweep_finished", extra=summary)
            except Exception:
                # The loop itself must survive anything, including the database
                # being unreachable. A worker that exits on the first bad minute is
                # a worker somebody has to notice and restart.
                logger.exception("worker.sweep_failed")

            took = dt.datetime.now(dt.UTC) - started
            await asyncio.sleep(max(0.0, (interval - took).total_seconds()))
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
