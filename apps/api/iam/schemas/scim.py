"""The SCIM resource shapes, as the spec defines them.

Two things about this file look like mistakes and are not.

**The capital letters.** ``Resources`` and ``Operations`` are capitalised in the
spec while every other field is camelCase. It is inconsistent and it is
normative, so we match it. A lowercase ``operations`` is silently ignored by the
provider, which shows up as a PATCH that returns 200 and changes nothing.

**The aliases.** SCIM is camelCase and our columns are snake_case, so every field
carries an alias. ``populate_by_name`` is on so our own code can build these with
Python names while the wire keeps the spec's.

Everything here is JSON, so unlike the SAML half it runs and is tested anywhere.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from iam.scim.constants import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_SCHEMA,
    LIST_RESPONSE_SCHEMA,
    PATCH_OP_SCHEMA,
    USER_SCHEMA,
)


class ScimModel(BaseModel):
    """Base for everything on the wire.

    ``populate_by_name`` lets our code use Python names; the alias is what gets
    serialised. ``extra="allow"`` on inbound resources is deliberate and
    explained on ScimUser.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class Meta(ScimModel):
    """The bookkeeping SCIM attaches to every resource."""

    resource_type: str = Field(alias="resourceType")
    created: dt.datetime | None = None
    last_modified: dt.datetime | None = Field(default=None, alias="lastModified")
    location: str | None = None
    version: str | None = Field(
        default=None,
        description=(
            "An ETag. Providers use it for conditional updates; we send it so a "
            "client that cares can, and we do not require it back."
        ),
    )


class Name(ScimModel):
    """A person's name, split the way SCIM splits it."""

    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")
    formatted: str | None = None


class Email(ScimModel):
    """One address. SCIM sends a list even when there is only ever one."""

    value: str
    type: str | None = "work"
    primary: bool | None = True


class MemberRef(ScimModel):
    """A pointer from one resource to another.

    ``$ref`` is a URL to the thing pointed at. Providers largely ignore it and
    the spec asks for it, so it goes in.
    """

    value: str = Field(description="The id of the referenced resource.")
    display: str | None = None
    ref: str | None = Field(default=None, alias="$ref")
    type: str | None = None


class EnterpriseUser(ScimModel):
    """The bits an HRMS cares about, which the base User schema leaves out.

    Deliberately an extension rather than core: a provider has to name the URN to
    send these, so receiving them is always something the other side chose.
    """

    employee_number: str | None = Field(default=None, alias="employeeNumber")
    department: str | None = None
    manager: MemberRef | None = None


class ScimUser(ScimModel):
    """A person, in SCIM's shape.

    ``extra="allow"`` is inherited on purpose. Providers send attributes we don't
    model — ``locale``, ``timezone``, ``phoneNumbers``, whole extension URNs —
    and the spec says to ignore what you don't understand rather than reject it.
    Rejecting means a provider whose default profile includes one extra field
    cannot create anybody here at all.
    """

    schemas: list[str] = Field(default_factory=lambda: [USER_SCHEMA])
    id: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")

    user_name: str = Field(alias="userName")
    name: Name | None = None
    display_name: str | None = Field(default=None, alias="displayName")
    emails: list[Email] = Field(default_factory=list)

    active: bool = True

    groups: list[MemberRef] = Field(
        default_factory=list,
        description=(
            "Read-only. Group membership is changed by PATCHing the group, not "
            "the person — see the note on ScimGroup.members."
        ),
    )

    enterprise: EnterpriseUser | None = Field(default=None, alias=ENTERPRISE_USER_SCHEMA)

    meta: Meta | None = None

    @property
    def primary_email(self) -> str | None:
        """The address to use, preferring the one marked primary.

        A provider that sends several and marks none primary still has to resolve
        to something, so the first is taken rather than nothing — an account with
        no email is worse than an account with the wrong one of two.
        """
        for email in self.emails:
            if email.primary and email.value:
                return email.value
        return next((email.value for email in self.emails if email.value), None)


class ScimGroup(ScimModel):
    """A group, in SCIM's shape."""

    schemas: list[str] = Field(default_factory=lambda: [GROUP_SCHEMA])
    id: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")

    display_name: str = Field(alias="displayName")

    members: list[MemberRef] = Field(
        default_factory=list,
        description=(
            "Who is in the group. This is the writable side of membership: a "
            "provider adds somebody by PATCHing the group here, and User.groups "
            "is the read-only reflection of it."
        ),
    )

    meta: Meta | None = None


class ListResponse(ScimModel):
    """The envelope around any list of resources.

    Paging is 1-based: the first item is startIndex 1, not 0. Sending 0 makes a
    provider request the same page forever, so the off-by-one here is load-bearing.
    """

    schemas: list[str] = Field(default_factory=lambda: [LIST_RESPONSE_SCHEMA])
    total_results: int = Field(alias="totalResults")
    start_index: int = Field(default=1, alias="startIndex")
    items_per_page: int = Field(alias="itemsPerPage")
    resources: list[dict[str, Any]] = Field(default_factory=list, alias="Resources")


PATCH_OPS = ("add", "remove", "replace")


class PatchOperation(ScimModel):
    """One change inside a PATCH.

    ``value`` is deliberately untyped. It is a scalar for ``replace active``, an
    object for ``replace`` on a complex attribute, and a list for ``add members``,
    and pinning it to one of those breaks the other two.
    """

    op: str
    path: str | None = None
    value: Any = None

    @field_validator("op")
    @classmethod
    def _normalise_op(cls, value: str) -> str:
        """Lowercase it, and refuse anything that isn't a real operation.

        The spec says these are case-insensitive and providers genuinely differ:
        Entra sends ``Add``, most others send ``add``, and nothing stops one
        sending ``REPLACE``. Spelling the accepted casings out as a fixed list
        works against whichever provider you tested with and rejects the next
        one, so this normalises instead of enumerating.
        """
        lowered = value.strip().lower()
        if lowered not in PATCH_OPS:
            raise ValueError(f"{value!r} is not a SCIM patch operation ({', '.join(PATCH_OPS)})")
        return lowered

    @property
    def operation(self) -> str:
        """The op, already lowercased by the validator."""
        return self.op


class PatchRequest(ScimModel):
    """A set of changes to apply to one resource.

    This is how deprovisioning arrives. When somebody leaves, the provider does
    not delete them — it sends ``replace active false``, and that one operation
    is the most important thing this server handles.
    """

    schemas: list[str] = Field(default_factory=lambda: [PATCH_OP_SCHEMA])
    operations: list[PatchOperation] = Field(alias="Operations")
