"""The fixed sets of values used across the tables.

These are stored as plain text columns with a rule limiting what can go in them,
rather than as real Postgres enum types. Adding a value to a real Postgres enum
needs an ALTER TYPE, which is awkward in a migration. Swapping a rule is a normal
drop-and-add.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum

ENUM_LENGTH = 32


def enum_type(enum_cls: type[StrEnum]) -> SAEnum:
    """Store an enum as a text column with a rule on the allowed values.

    Don't drop values_callable. Without it SQLAlchemy saves the enum's Python name
    ('ADMIN') while everything else in the codebase and the API uses the lowercase
    value ('admin'). Two things break when they disagree: a default of 'employee'
    fails the rule that only allows 'EMPLOYEE', and writing
    `WHERE platform_role = 'admin'` by hand quietly matches zero rows.
    """
    return SAEnum(
        enum_cls,
        native_enum=False,
        length=ENUM_LENGTH,
        validate_strings=True,
        values_callable=lambda cls: [member.value for member in cls],
    )


class IdentitySource(StrEnum):
    """Where a record came from.

    Worth tracking, because you shouldn't hand-edit something SCIM created. The
    next sync would just put it back.
    """

    SCIM = "scim"
    """Created by the identity provider over SCIM (P3)."""

    JIT = "jit"
    """Created on first login because SCIM hadn't sent them yet (P2)."""

    MANUAL = "manual"
    """Someone typed it into the console."""

    SEED = "seed"
    """Made up by the demo data script."""


class PlatformRole(StrEnum):
    """What someone can do inside this console.

    Four broad roles, stored straight on the user for now. P4 works them out from
    someone's access grants instead, and this column becomes a cached copy rather
    than the real answer.
    """

    ADMIN = "admin"
    HELPDESK = "helpdesk"
    AUDITOR = "auditor"
    EMPLOYEE = "employee"


class AppProtocol(StrEnum):
    """How an application integrates with this control plane."""

    SAML2 = "saml2"
    OIDC = "oidc"
    SCIM2 = "scim2"
    NONE = "none"
    """We track who has access, but we're not wired into it technically."""


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
    """Blocked because they weren't allowed. Kept separate from failure because a
    lot of denials means someone's probing, whereas a lot of failures means
    something's broken."""
