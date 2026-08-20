"""Pushing accounts outward: the SCIM client half.

P3 made us a SCIM server — a provider writes into our directory. This is the other
direction, where we write into somebody else's.

- addresses.py — whether we are willing to send anything to a given address (ADR 0007)
- client.py — the requests themselves, one at a time, no retries

Coming in the rest of P6: the sync that decides what to push and when, and the
console screen that shows what went where.
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

__all__ = [
    "Decision",
    "OutboundScim",
    "PushFailed",
    "RemoteAccount",
    "UnusableTarget",
    "check",
    "deactivate_patch",
    "reactivate_patch",
    "user_payload",
]
