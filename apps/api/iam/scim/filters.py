"""The part of SCIM's filter grammar we accept, and the part we refuse.

SCIM defines a full query language: ``and``, ``or``, ``not``, grouping,
``pr`` (present), ``co`` (contains), ``sw``, ``ew``, ``gt``, ``ge``, ``lt``,
``le``, and complex attribute paths like
``emails[type eq "work"].value``. Implementing all of it means writing a parser
and then translating its tree into SQL.

We accept a subset, deliberately:

    userName eq "ada@demo.local"
    externalId eq "9f1c-..."
    displayName eq "Engineering"
    active eq true

That is not a guess about what is enough. It is what providers actually send
during a sync: before creating anything, a provider asks "do you already have
this one?", and that question is a single ``eq`` on the attribute it identifies
people by. Okta, authentik and Entra all do exactly this.

Anything outside the subset is refused with ``invalidFilter`` and a message
naming what was unsupported. That is the important half of the design. A filter
we don't understand must never be treated as "no filter", because the request
that asks "do you have userName X" would then be answered with the entire
directory — and a provider reading the first page of that gets somebody else's
account and merrily writes to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from iam.scim.errors import bad_filter

# attribute, operator, value. The value is either a quoted string or a bare
# true/false. Anchored at both ends so a filter with anything trailing — an
# `and`, a bracket, a second clause — fails to match rather than being read as
# just its first clause.
_SIMPLE_EQ = re.compile(
    r"""
    ^\s*
    (?P<attribute>[A-Za-z][A-Za-z0-9_.\$]*)   # userName, externalId, urn:...:attr
    \s+(?P<operator>[A-Za-z]{2})\s+           # eq, co, sw, ...
    (?:
        "(?P<quoted>(?:[^"\\]|\\.)*)"         # "ada@demo.local"
      | (?P<bare>true|false)                  # active eq true
    )
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)

SUPPORTED_OPERATOR = "eq"

# What a filter is allowed to be about, mapped from the SCIM attribute name to
# the column it means. Lowercased keys because SCIM attribute names are
# case-insensitive and providers are inconsistent about the capital N in
# userName.
USER_FILTER_ATTRIBUTES = {
    "username": "user_name",
    "externalid": "external_id",
    "active": "active",
    "emails.value": "email",
    "emails": "email",
}

GROUP_FILTER_ATTRIBUTES = {
    "displayname": "name",
    "externalid": "external_id",
}


@dataclass(frozen=True, slots=True)
class Comparison:
    """One ``attribute eq value``, already mapped to the column it means."""

    column: str
    value: str | bool

    @property
    def is_boolean(self) -> bool:
        return isinstance(self.value, bool)


def _unescape(quoted: str) -> str:
    r"""Undo the escaping inside a quoted filter value.

    SCIM strings are JSON strings, so a quote inside one arrives as \" and a
    backslash as \\. Leaving those in means a search for a name containing an
    apostrophe-escaped character quietly matches nothing.
    """
    return quoted.replace('\\"', '"').replace("\\\\", "\\")


def parse_filter(expression: str, attributes: dict[str, str]) -> Comparison:
    """Read a filter, or refuse it with a message that says why.

    Args:
        expression: The raw ``filter`` query parameter.
        attributes: Which SCIM attribute names this resource allows, mapped to
            the column each one means.

    Raises:
        ScimError: The filter is malformed, uses an operator or an attribute we
            don't support, or contains more than one clause. Always
            ``invalidFilter``, never silently ignored — see the module docstring
            for why that distinction matters more than it looks.
    """
    match = _SIMPLE_EQ.match(expression)
    if match is None:
        raise bad_filter(
            f"Cannot read the filter {expression!r}. This server supports a single "
            'comparison, like: userName eq "ada@demo.local". Combining clauses with '
            "and/or, and the co/sw/pr operators, are not supported."
        )

    operator = match.group("operator").lower()
    if operator != SUPPORTED_OPERATOR:
        raise bad_filter(
            f"The {operator!r} operator is not supported. This server supports "
            f"{SUPPORTED_OPERATOR!r} only."
        )

    attribute = match.group("attribute").lower()
    column = attributes.get(attribute)
    if column is None:
        allowed = ", ".join(sorted(attributes))
        raise bad_filter(
            f"Cannot filter on {match.group('attribute')!r}. Supported attributes: {allowed}."
        )

    bare = match.group("bare")
    if bare is not None:
        return Comparison(column=column, value=bare.lower() == "true")

    return Comparison(column=column, value=_unescape(match.group("quoted") or ""))


def parse_user_filter(expression: str) -> Comparison:
    return parse_filter(expression, USER_FILTER_ATTRIBUTES)


def parse_group_filter(expression: str) -> Comparison:
    return parse_filter(expression, GROUP_FILTER_ATTRIBUTES)
