"""Pushing accounts outward: the SCIM client half.

P3 made us a SCIM server — a provider writes into our directory. This is the other
direction, where we write into somebody else's.

- addresses.py — whether we are willing to send anything to a given address (ADR 0007)
- client.py — the requests themselves, one at a time, no retries
- sync.py — which requests to make, and when

Coming in the rest of P6: the console screen that shows what went where, and a
downstream to point it at.
"""

from __future__ import annotations

from iam.provisioning.addresses import Decision, UnusableTarget, check
from iam.provisioning.client import (
    OutboundScim,
    PushFailed,
    RemoteAccount,
    deactivate_patch,
    reactivate_patch,
    user_payload,
)
from iam.provisioning.sync import (
    AlreadyRunning,
    SyncOutcome,
    count_waiting,
    entitled_people,
    push_one,
    reconcile,
)

__all__ = [
    "AlreadyRunning",
    "Decision",
    "OutboundScim",
    "PushFailed",
    "RemoteAccount",
    "SyncOutcome",
    "UnusableTarget",
    "check",
    "count_waiting",
    "deactivate_patch",
    "entitled_people",
    "push_one",
    "reactivate_patch",
    "reconcile",
    "user_payload",
]
