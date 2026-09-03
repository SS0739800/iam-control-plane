"""The background sweep: pushing changes without somebody pressing a button.

Before this, provisioning only ran inside the request that asked for it, so a
leaver's account stayed live in a downstream system until somebody opened the
console and pressed Sync now. This has actually caused a live gap before: Okta
deactivated someone at 8:51:40, the last sync had run at 8:51:12, and the account
stayed active until a person noticed.

This runs reconcile() on a timer instead of a queue, since reconcile() already
compares "who should have an account" against "what the system currently has" and
fixes the difference — a missed sweep just means the next one catches it, while a
dropped queue message means nobody notices. It's also simpler: no broker, no
dead-letter handling, no ordering questions.

This does not force a retry on links that already hit their attempt limit —
that's left for a person pressing Sync now, since doing it automatically every
few minutes would turn a permanently broken target into steady load and log
noise. And it never runs two sweeps against the same target at once: reconcile()
takes a lease on the target and refuses if another sync already holds it (needed
across multiple worker machines, since the loop below alone only protects one
process).
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
from iam.provisioning import AlreadyRunning, reconcile

logger = logging.getLogger(__name__)


async def sweep_once(
    sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    now: dt.datetime,
) -> dict[str, int]:
    """Reconcile every enabled target, once.

    Each target gets its own session and correlation id, so one target's failure
    can't roll back another's work.

    Returns a small summary for the log line and for tests to assert on.
    """
    async with sessionmaker() as session:
        targets = list(
            await session.scalars(
                select(ProvisioningTarget)
                .where(ProvisioningTarget.enabled.is_(True))
                # Eager load: the application is read while building audit
                # entries, and a lazy load there raises MissingGreenlet.
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
                    # Removed or paused between the listing and now.
                    continue

                try:
                    outcome = await reconcile(
                        session, fresh, settings, now=now, correlation_id=correlation_id
                    )
                except AlreadyRunning:
                    # Another worker machine or a manual sync already has the
                    # lease. Skip it; the next sweep will catch up either way.
                    logger.info("worker.target_busy", extra={"target": fresh.base_url})
                    continue

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
            # One target failing (downstream down, a rotated token, an expired
            # certificate) must not stop the rest.
            summary["failed"] += 1
            logger.exception(
                "worker.target_failed",
                extra={"target": target.base_url, "correlation_id": str(correlation_id)},
            )

    return summary


async def run_forever(settings: Settings | None = None) -> None:
    """Sweep, wait, sweep again, until something stops the process.

    The interval is a floor, not a fixed schedule: a slow sweep just delays the
    next one instead of overlapping it.
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
                # The loop must survive anything, including the database being
                # unreachable, or somebody has to notice and restart the worker.
                logger.exception("worker.sweep_failed")

            took = dt.datetime.now(dt.UTC) - started
            await asyncio.sleep(max(0.0, (interval - took).total_seconds()))
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
