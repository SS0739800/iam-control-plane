"""The part of SCIM's filter grammar we accept, and the part we refuse.

SCIM defines a full query language: `and`, `or`, `not`, grouping, `pr`
(present), `co` (contains), `sw`, `ew`, `gt`, `ge`, `lt`, `le`, and complex
attribute paths like `emails[type eq "work"].value`. We only accept:

    userName eq "ada@demo.local"
    userName eq ada@demo.local        (unquoted - authentik sends this)
    externalId eq "9f1c-..."
    displayName eq "Engineering"
    active eq true

That matches what providers actually send during a sync: before creating
anything, a provider asks "do you already have this one?", which is a single
`eq` on the attribute it identifies people by. Okta, authentik, and Entra all
do this.

Anything outside that subset is refused with `invalidFilter`, naming what
was unsupported. This matters for security: a filter we don't understand
must never be treated as "no filter", or a request asking "do you have
userName X" would get answered with the entire directory - handing the
provider someone else's account to write to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from iam.scim.errors import bad_filter

# attribute, operator, value. The value is a quoted string, or an unquoted
# run of non-space characters.
#
# Anchored at both ends - that's what keeps the unquoted form safe. A second
# clause like `userName eq a and active eq true` has a space after the `a`,
# so the whole expression fails to match instead of matching just the first part.
_SIMPLE_EQ = re.compile(
    r"""
    ^\s*
    (?P<attribute>[A-Za-z][A-Za-z0-9_.\$]*)   # userName, externalId, urn:...:attr
    \s+(?P<operator>[A-Za-z]{2})\s+           # eq, co, sw, ...
    (?:
        "(?P<quoted>(?:[^"\\]|\\.)*)"         # userName eq "ada@demo.local"
      | (?P<bare>\S+)                         # userName eq akadmin, active eq true
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
    """One `attribute eq value`, already mapped to the column it means."""

    column: str
    value: str | bool

    @property
    def is_boolean(self) -> bool:
        return isinstance(self.value, bool)


def _unescape(quoted: str) -> str:
    r"""Undo the escaping inside a quoted filter value.

    SCIM strings are JSON strings, so a quote inside one arrives as \" and a
    backslash as \\. Leaving those escaped would make a search for a name
    containing one of those characters silently match nothing.
    """
    return quoted.replace('\\"', '"').replace("\\\\", "\\")


def parse_filter(expression: str, attributes: dict[str, str]) -> Comparison:
    """Read a filter, or refuse it with a message that says why.

    Args:
        expression: The raw ``filter`` query parameter.
        attributes: Which SCIM attribute names this resource allows, mapped to
            the column each one means.

    Raises:
        ScimError: The filter is malformed, uses an operator or an attribute
            we don't support, or contains more than one clause. Always
            `invalidFilter`, never silently ignored - see the module
            docstring for why that matters.
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
        # true and false are booleans; anything else unquoted is a string.
        #
        # The spec wants a quoted JSON string here, but authentik sends
        # `userName eq akadmin` with no quotes. Rejecting that would break
        # the first request a sync makes, so both forms are accepted and
        # tested.
        if bare.lower() in ("true", "false"):
            return Comparison(column=column, value=bare.lower() == "true")
        return Comparison(column=column, value=bare)

    return Comparison(column=column, value=_unescape(match.group("quoted") or ""))


def parse_user_filter(expression: str) -> Comparison:
    return parse_filter(expression, USER_FILTER_ATTRIBUTES)


def parse_group_filter(expression: str) -> Comparison:
    return parse_filter(expression, GROUP_FILTER_ATTRIBUTES)
