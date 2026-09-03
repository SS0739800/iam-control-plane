"""Tests for the parts of SCIM that are pure logic: filters, shapes, mapping.

No database and no network, so these run anywhere. The endpoints that sit on
top of this get their own tests; this covers the layer they all depend on,
where a quiet mistake would be wrong everywhere at once.

The documents in here are shaped the way authentik, Okta, and Entra actually
send them - capital `Operations`, the enterprise extension URN as a key,
extra attributes we don't model. A tidied-up invention would pass while the
real thing failed.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from pydantic import ValidationError

from iam.models.enums import IdentitySource, PlatformRole
from iam.models.group import Group
from iam.models.user import User
from iam.schemas.scim import PatchRequest, ScimUser
from iam.scim.constants import ENTERPRISE_USER_SCHEMA, USER_SCHEMA
from iam.scim.errors import ScimError, ScimType, already_exists
from iam.scim.filters import parse_group_filter, parse_user_filter
from iam.scim.mapping import (
    WRITABLE_USER_FIELDS,
    apply_user,
    group_to_scim,
    user_fields_from_scim,
    user_to_scim,
)

BASE_URL = "http://localhost:8080"
NOW = dt.datetime(2026, 8, 16, 12, 0, 0, tzinfo=dt.UTC)


def make_user(**overrides: object) -> User:
    user = User(
        user_name="ada.bergman@demo.local",
        email="ada.bergman@demo.local",
        given_name="Ada",
        family_name="Bergman",
        display_name="Ada Bergman",
        active=True,
        platform_role=PlatformRole.EMPLOYEE,
        source=IdentitySource.SCIM,
        external_id="ak-9f1c",
    )
    user.id = uuid.uuid4()
    user.created_at = NOW
    user.updated_at = NOW
    for field, value in overrides.items():
        setattr(user, field, value)
    return user


def make_group(**overrides: object) -> Group:
    group = Group(name="Engineering", external_id="ak-grp-1", source=IdentitySource.SCIM)
    group.id = uuid.uuid4()
    group.created_at = NOW
    group.updated_at = NOW
    for field, value in overrides.items():
        setattr(group, field, value)
    return group


# --------------------------------------------------------------- the filters


@pytest.mark.parametrize(
    ("expression", "column", "value"),
    [
        ('userName eq "ada@demo.local"', "user_name", "ada@demo.local"),
        ('externalId eq "ak-9f1c"', "external_id", "ak-9f1c"),
        ("active eq true", "active", True),
        ("active eq false", "active", False),
        # Attribute names are case-insensitive in SCIM and providers disagree
        # about the capital N.
        ('username eq "ada@demo.local"', "user_name", "ada@demo.local"),
        ('USERNAME EQ "ada@demo.local"', "user_name", "ada@demo.local"),
        # Unquoted. The spec wants a quoted JSON string here, but authentik
        # sends this instead - found by watching a real sync stall on its
        # very first request until this was accepted.
        ("userName eq akadmin", "user_name", "akadmin"),
        ("externalId eq 6", "external_id", "6"),
    ],
)
def test_reads_the_filters_providers_actually_send(
    expression: str, column: str, value: object
) -> None:
    parsed = parse_user_filter(expression)

    assert parsed.column == column
    assert parsed.value == value


def test_a_quoted_value_keeps_its_escaped_characters() -> None:
    parsed = parse_user_filter(r'displayName eq "O\"Brien"'.replace("displayName", "userName"))

    assert parsed.value == 'O"Brien'


def test_group_filters_are_about_group_attributes() -> None:
    assert parse_group_filter('displayName eq "Engineering"').column == "name"


@pytest.mark.parametrize(
    "expression",
    [
        'userName co "ada"',
        'userName sw "ada"',
        "userName pr",
        'emails[type eq "work"].value eq "x"',
    ],
)
def test_operators_we_do_not_support_are_refused(expression: str) -> None:
    with pytest.raises(ScimError) as raised:
        parse_user_filter(expression)

    assert raised.value.status_code == 400
    assert raised.value.scim_type == ScimType.INVALID_FILTER


def test_an_unquoted_true_is_still_a_boolean() -> None:
    """Accepting unquoted values shouldn't turn `active eq true` into the
    string "true", which would match nobody and look like an empty directory."""
    assert parse_user_filter("active eq true").value is True
    assert parse_user_filter("active eq false").value is False


def test_a_compound_filter_is_refused_rather_than_half_read() -> None:
    """Reading only the first clause of `userName eq "a" and active eq true`
    would answer a narrower question than was asked. Worse is treating an
    unreadable filter as no filter: the provider asks "do you have this one
    person" and gets the whole directory, then writes to whoever came back
    first.
    """
    with pytest.raises(ScimError) as raised:
        parse_user_filter('userName eq "ada@demo.local" and active eq true')

    assert raised.value.scim_type == ScimType.INVALID_FILTER

    # Same without quotes, which is the form that made this possible.
    with pytest.raises(ScimError):
        parse_user_filter("userName eq ada and active eq true")


def test_filtering_on_something_we_do_not_index_says_what_is_allowed() -> None:
    with pytest.raises(ScimError, match="Supported attributes"):
        parse_user_filter('nickName eq "ada"')


# ------------------------------------------------------------- the error shape


def test_a_conflict_says_uniqueness_so_the_provider_can_recover() -> None:
    """A provider reading scimType=uniqueness knows to update instead of
    create. A bare 400 makes it give up, and the sync reports failure
    forever over somebody who exists just fine."""
    error = already_exists("userName", "ada@demo.local")
    document = error.as_document()

    assert error.status_code == 409
    assert document["scimType"] == ScimType.UNIQUENESS
    assert document["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_the_status_is_a_string_not_a_number() -> None:
    """Per the spec - providers do reject the numeric form."""
    document = ScimError(404, "gone").as_document()

    assert document["status"] == "404"
    assert isinstance(document["status"], str)


def test_an_error_without_a_scim_type_leaves_the_field_out() -> None:
    assert "scimType" not in ScimError(500, "boom").as_document()


# ------------------------------------------------------ reading what they send


def test_reads_the_document_authentik_posts() -> None:
    scim = ScimUser.model_validate(
        {
            "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
            "userName": "ada.bergman@demo.local",
            "name": {"givenName": "Ada", "familyName": "Bergman"},
            "emails": [{"value": "ada@demo.local", "type": "work", "primary": True}],
            "externalId": "ak-9f1c",
            "active": True,
            ENTERPRISE_USER_SCHEMA: {"employeeNumber": "E-1", "department": "Engineering"},
        }
    )

    assert scim.user_name == "ada.bergman@demo.local"
    assert scim.primary_email == "ada@demo.local"
    assert scim.enterprise is not None
    assert scim.enterprise.department == "Engineering"


def test_attributes_we_do_not_model_are_kept_not_rejected() -> None:
    """The spec says ignore what you don't understand. Rejecting would mean
    a provider whose default profile has one extra field can't create
    anybody here."""
    scim = ScimUser.model_validate(
        {"userName": "ada@demo.local", "locale": "en-US", "phoneNumbers": [{"value": "123"}]}
    )

    assert scim.user_name == "ada@demo.local"
    assert scim.model_extra is not None
    assert "locale" in scim.model_extra


def test_the_primary_email_wins_over_the_others() -> None:
    scim = ScimUser.model_validate(
        {
            "userName": "ada@demo.local",
            "emails": [
                {"value": "personal@example.com", "primary": False},
                {"value": "work@demo.local", "primary": True},
            ],
        }
    )

    assert scim.primary_email == "work@demo.local"


def test_a_list_of_emails_with_none_marked_primary_still_resolves() -> None:
    """An account with the wrong one of two addresses beats one with none."""
    scim = ScimUser.model_validate(
        {"userName": "ada@demo.local", "emails": [{"value": "first@demo.local", "primary": False}]}
    )

    assert scim.primary_email == "first@demo.local"


@pytest.mark.parametrize("op", ["replace", "Replace", "REPLACE", " replace "])
def test_patch_operations_are_case_insensitive(op: str) -> None:
    """Entra sends "Add", most others send "add". Comparing the raw value
    would work against whichever one you tested with and fail on the other."""
    patch = PatchRequest.model_validate(
        {"Operations": [{"op": op, "path": "active", "value": False}]}
    )

    assert patch.operations[0].operation == "replace"


def test_an_operation_that_is_not_a_real_one_is_refused() -> None:
    """Normalizing the case shouldn't turn into accepting anything at all."""
    with pytest.raises(ValidationError):
        PatchRequest.model_validate({"Operations": [{"op": "obliterate", "value": 1}]})


def test_patch_reads_the_capitalised_operations_key() -> None:
    """Capitalized in the spec. A lowercase key would parse as no
    operations at all - a PATCH that returns 200 and changes nothing."""
    patch = PatchRequest.model_validate(
        {"Operations": [{"op": "replace", "value": {"active": False}}]}
    )

    assert len(patch.operations) == 1


# ------------------------------------------------------- what we send them


def test_a_person_comes_back_in_scim_shape() -> None:
    scim = user_to_scim(make_user(), base_url=BASE_URL)
    document = scim.model_dump(by_alias=True, exclude_none=True)

    assert document["userName"] == "ada.bergman@demo.local"
    assert document["externalId"] == "ak-9f1c"
    assert document["name"]["givenName"] == "Ada"
    assert document["emails"][0]["value"] == "ada.bergman@demo.local"
    assert document["active"] is True


def test_the_name_is_sent_both_split_and_formatted() -> None:
    """Providers read whichever one they were built around; leaving one
    out is why a display name never updates for some of them."""
    scim = user_to_scim(make_user(), base_url=BASE_URL)

    assert scim.name is not None
    assert scim.name.formatted == "Ada Bergman"
    assert scim.name.given_name == "Ada"


def test_meta_points_back_at_the_resource() -> None:
    user = make_user()

    scim = user_to_scim(user, base_url=BASE_URL)

    assert scim.meta is not None
    assert scim.meta.resource_type == "User"
    assert scim.meta.location == f"{BASE_URL}/scim/v2/Users/{user.id}"
    assert scim.meta.version


def test_the_version_changes_when_the_row_does() -> None:
    unchanged = user_to_scim(make_user(), base_url=BASE_URL)
    later = user_to_scim(make_user(updated_at=NOW + dt.timedelta(minutes=1)), base_url=BASE_URL)

    assert unchanged.meta is not None and later.meta is not None
    assert unchanged.meta.version != later.meta.version


def test_the_enterprise_extension_only_appears_when_there_is_something_in_it() -> None:
    """A provider has to name the URN to send these, so we shouldn't claim
    to support it on a record that has none of it."""
    plain = user_to_scim(make_user(employee_number=None, department=None), base_url=BASE_URL)
    with_hr = user_to_scim(make_user(department="Engineering"), base_url=BASE_URL)

    assert plain.enterprise is None
    assert ENTERPRISE_USER_SCHEMA not in plain.schemas
    assert with_hr.enterprise is not None
    assert ENTERPRISE_USER_SCHEMA in with_hr.schemas


def test_a_group_comes_back_with_its_members() -> None:
    group = make_group()
    member = make_user()

    scim = group_to_scim(group, base_url=BASE_URL, members=[member])

    assert scim.display_name == "Engineering"
    assert scim.members[0].value == str(member.id)
    assert scim.members[0].display == "Ada Bergman"


# --------------------------------------------------- what they may write


def test_scim_cannot_set_what_somebody_is_allowed_to_do() -> None:
    """Nothing upstream should be able to make itself an admin here by
    editing a directory record."""
    assert "platform_role" not in WRITABLE_USER_FIELDS
    assert "source" not in WRITABLE_USER_FIELDS

    user = make_user(platform_role=PlatformRole.EMPLOYEE)
    changed = apply_user(user, {"platform_role": PlatformRole.ADMIN, "display_name": "Ada B"})

    assert user.platform_role is PlatformRole.EMPLOYEE
    assert changed == ("display_name",)


def test_a_document_that_omits_a_field_does_not_blank_it() -> None:
    """A partial resource on PUT shouldn't read as "set the rest to null",
    or a sync that tidies one record blanks everybody's department."""
    scim = ScimUser.model_validate({"userName": "ada@demo.local", "active": True})

    values = user_fields_from_scim(scim)

    assert "department" not in values
    assert "employee_number" not in values
    assert "external_id" not in values


def test_deactivating_comes_through_as_a_field_we_write() -> None:
    """This is deprovisioning - it arrives as one boolean."""
    scim = ScimUser.model_validate({"userName": "ada@demo.local", "active": False})

    values = user_fields_from_scim(scim)
    user = make_user(active=True)
    changed = apply_user(user, values)

    assert values["active"] is False
    assert user.active is False
    assert "active" in changed


def test_a_display_name_is_worked_out_when_the_provider_sends_none() -> None:
    """authentik sends no displayName for some profiles, and a blank name
    in the console is a bug people report."""
    scim = ScimUser.model_validate(
        {"userName": "ada@demo.local", "name": {"givenName": "Ada", "familyName": "Bergman"}}
    )

    assert user_fields_from_scim(scim)["display_name"] == "Ada Bergman"


def test_a_person_with_only_a_username_still_gets_a_display_name() -> None:
    scim = ScimUser.model_validate({"userName": "ada@demo.local"})

    assert user_fields_from_scim(scim)["display_name"] == "ada@demo.local"


def test_applying_the_same_document_twice_reports_no_changes() -> None:
    """Providers re-send unchanged records constantly during a full sync.
    Every one writing an audit entry would bury the real changes."""
    user = make_user()
    values = user_fields_from_scim(user_to_scim(user, base_url=BASE_URL))

    assert apply_user(user, values) == ()
