"""Audit logging.

Use append_event to write entries. Don't build an AuditEvent yourself — the
fingerprint that links it to the entry before it gets worked out inside
append_event, and a hand-made row would break the tamper check.
"""

from __future__ import annotations

from iam.audit.chain import (
    AuditDraft,
    ChainVerification,
    append_event,
    canonical_form,
    compute_hash,
    hash_for_event,
    verify_chain,
)

__all__ = [
    "AuditDraft",
    "ChainVerification",
    "append_event",
    "canonical_form",
    "compute_hash",
    "hash_for_event",
    "verify_chain",
]
