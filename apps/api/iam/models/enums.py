"""The fixed sets of values used across the tables.

Stored as text columns with a CHECK constraint, not real Postgres enum types,
so adding a value later is just a migration that swaps the CHECK instead of
an ALTER TYPE. Two things enforce the allowed values: SQLAlchemy's
validate_strings=True on writes through the ORM, and the CHECK constraint
(create_constraint=True) for anything that writes SQL directly. Without the
CHECK, a raw SQL write could store an unlisted value and nothing would catch it.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum

ENUM_LENGTH = 32


def enum_type(enum_cls: type[StrEnum]) -> SAEnum:
    """Store an enum as a text column with a CHECK on the allowed values.

    Keep values_callable: without it SQLAlchemy stores the enum's Python name
    ('ADMIN') instead of its lowercase value ('admin'), which the rest of the
    codebase and API use, and a hand-written query like
    `WHERE platform_role = 'admin'` would silently match nothing.
    """
    return SAEnum(
        enum_cls,
        native_enum=False,
        length=ENUM_LENGTH,
        validate_strings=True,
        # Adds a database-level CHECK so raw SQL can't store an unlisted value.
        create_constraint=True,
        values_callable=lambda cls: [member.value for member in cls],
    )


class IdentitySource(StrEnum):
    """Where a record came from. Don't hand-edit something SCIM created;
    the next sync will overwrite it."""

    SCIM = "scim"
    """Created by the identity provider over SCIM."""

    JIT = "jit"
    """Created on first login because SCIM hadn't sent them yet."""

    MANUAL = "manual"
    """Someone typed it into the console."""

    SEED = "seed"
    """Made up by the demo data script."""


class PlatformRole(StrEnum):
    """What someone can do inside this console.

    The role is decided by a user's role grants, not this column directly —
    the column is a cached copy, rebuilt whenever a grant changes.

    EMPLOYEE isn't a grantable role: it's what someone is when nothing has
    been granted to them, so there's never a role grant recording it.
    """

    ADMIN = "admin"
    HELPDESK = "helpdesk"
    AUDITOR = "auditor"
    EMPLOYEE = "employee"


class GrantSource(StrEnum):
    """How somebody came to have an access grant."""

    DIRECT = "direct"
    """An admin granted it in the console to this one person."""

    RULE = "rule"
    """An access rule gave it to them based on their attributes."""

    REQUEST = "request"
    """They asked for it and somebody approved."""

    SEED = "seed"
    """The demo data script. Never appears in a real deployment."""

    MIGRATED = "migrated"
    """The role was already on the user's row before grants existed, so
    who decided it and when was never recorded."""


class MembershipSource(StrEnum):
    """Why somebody is in a group.

    Three things add memberships (the provider, a console user, and access
    rules), and the rule engine must only remove what it added. Without this
    field, reconciling rules would delete provider-added memberships and the
    next sync would just put them back.
    """

    SCIM = "scim"
    """The provider put them here. Ours to read, not to remove."""

    MANUAL = "manual"
    """Somebody added them in the console."""

    RULE = "rule"
    """An access rule added them. The only kind the rule engine removes."""

    REQUEST = "request"
    """They asked for it and somebody approved. Kept separate from 'manual'
    since the request record holds the reason and the approver."""

    SEED = "seed"
    """Demo data."""


class RuleOperator(StrEnum):
    """How an access rule compares an attribute.

    Kept to a short, readable list (e.g. "department is Engineering")
    rather than a general expression language, so rules stay reviewable.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    IS_SET = "is_set"
    """Has any value at all for the attribute."""
    IS_NOT_SET = "is_not_set"


class RequestState(StrEnum):
    """Where an access request has got to.

    Every state after PENDING is final; requests aren't reopened.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    WITHDRAWN = "withdrawn"
    """The requester changed their mind."""

    CANCELLED = "cancelled"
    """Overtaken by events, usually the requester left or already has it."""


class LinkState(StrEnum):
    """Where one person's downstream account has got to.

    FAILED can mean the account exists (created fine, an update later
    failed) or doesn't. Telling those apart is the difference between
    retrying an update and creating a duplicate.
    """

    PENDING = "pending"
    """Should exist downstream and doesn't yet. Starting state for a new assignment."""

    ACTIVE = "active"
    """Exists and matches what we last sent."""

    FAILED = "failed"
    """The last attempt didn't work. remote_id says whether an account exists out there."""

    DEPROVISIONED = "deprovisioned"
    """Deactivated downstream. Kept rather than deleted so a rehire revives
    the account instead of creating a duplicate."""

    ORPHANED = "orphaned"
    """We were told to remove it and couldn't (target refused, or is gone).
    Distinct from FAILED because it means someone still has access we
    believe was removed — the case an access review needs to catch."""


class AppProtocol(StrEnum):
    """How an application integrates with this control plane."""

    SAML2 = "saml2"
    OIDC = "oidc"
    SCIM2 = "scim2"
    NONE = "none"
    """We track who has access but aren't technically integrated with it."""


class AppStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class PrincipalType(StrEnum):
    """What kind of thing an application is assigned to."""

    USER = "user"
    GROUP = "group"


class ActorType(StrEnum):
    """What kind of thing did this."""

    USER = "user"
    """A person clicking around in the console."""

    SYSTEM = "system"
    """One of our own scheduled jobs."""

    IDP = "idp"
    """The identity provider, over SAML or SCIM."""


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    """Attempted and errored."""

    DENIED = "denied"
    """Blocked because they weren't allowed. Kept separate from FAILURE: a
    spike in denials suggests probing, a spike in failures suggests a bug."""
