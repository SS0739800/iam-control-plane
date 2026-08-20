"""Pushing accounts outward: the SCIM client half.

P3 made us a SCIM server — a provider writes into our directory. This is the other
direction, where we write into somebody else's.

- addresses.py — whether we are willing to send anything to a given address (ADR 0007)

Coming in the rest of P6: the target model, the client that speaks SCIM outward, and
the console screen that shows what has been pushed where.
"""

from __future__ import annotations

from iam.provisioning.addresses import Decision, UnusableTarget, check

__all__ = ["Decision", "UnusableTarget", "check"]
