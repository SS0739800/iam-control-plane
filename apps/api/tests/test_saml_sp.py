"""Tests for our side of the login: metadata, the request, and the redirect.

No xmlsec involved, so these run anywhere.
"""

from __future__ import annotations

import base64
import datetime as dt
import zlib
from urllib.parse import parse_qs, urlparse

import pytest

from iam.saml.sp import (
    ServiceProvider,
    build_authn_request,
    deflate_and_encode,
    is_safe_return_path,
    login_redirect_url,
    new_relay_state,
    new_request_id,
)

BASE_URL = "https://iam.demo.local"
IDP_SSO_URL = "https://authentik.demo.local/application/saml/iam/sso/binding/redirect/"
ISSUED_AT = dt.datetime(2026, 8, 14, 12, 0, 0, tzinfo=dt.UTC)


@pytest.fixture
def sp() -> ServiceProvider:
    return ServiceProvider.from_base_url(BASE_URL)


def test_all_three_addresses_come_from_one_base(sp: ServiceProvider) -> None:
    """One thing to change when this moves off localhost."""
    assert sp.entity_id == "https://iam.demo.local/saml/metadata"
    assert sp.acs_url == "https://iam.demo.local/saml/acs"
    assert sp.slo_url == "https://iam.demo.local/saml/sls"


def test_a_trailing_slash_on_the_base_does_not_double_up() -> None:
    assert ServiceProvider.from_base_url("https://iam.demo.local/").acs_url == (
        "https://iam.demo.local/saml/acs"
    )


def test_metadata_says_where_to_send_the_answer(sp: ServiceProvider) -> None:
    xml = sp.metadata_xml()

    assert f'entityID="{sp.entity_id}"' in xml
    assert f'Location="{sp.acs_url}"' in xml


def test_metadata_asks_for_the_assertion_itself_to_be_signed(sp: ServiceProvider) -> None:
    """Signing only the envelope leaves the contents swappable."""
    assert 'WantAssertionsSigned="true"' in sp.metadata_xml()


def test_request_ids_are_unique_and_do_not_start_with_a_digit() -> None:
    """XML ids can't start with a number, and some providers reject the whole
    document rather than saying so."""
    ids = {new_request_id() for _ in range(200)}

    assert len(ids) == 200
    assert all(not value.lstrip("id-")[0].isdigit() or value.startswith("id-") for value in ids)
    assert all(value[0].isalpha() for value in ids)


def test_relay_states_are_unique() -> None:
    """A guessable one would let someone answer a request they didn't make."""
    tokens = {new_relay_state() for _ in range(200)}

    assert len(tokens) == 200
    assert all(len(token) >= 32 for token in tokens)


def test_the_request_carries_the_id_the_answer_must_quote(sp: ServiceProvider) -> None:
    request_id = "id-abc123"

    xml = build_authn_request(
        sp=sp, idp_sso_url=IDP_SSO_URL, request_id=request_id, issued_at=ISSUED_AT
    )

    assert f'ID="{request_id}"' in xml
    assert f"<saml:Issuer>{sp.entity_id}</saml:Issuer>" in xml
    assert f'AssertionConsumerServiceURL="{sp.acs_url}"' in xml
    assert f'Destination="{IDP_SSO_URL}"' in xml


def test_the_request_timestamp_is_utc_without_microseconds(sp: ServiceProvider) -> None:
    """Providers are fussy about this format and reject anything else."""
    xml = build_authn_request(
        sp=sp, idp_sso_url=IDP_SSO_URL, request_id="id-x", issued_at=ISSUED_AT
    )

    assert 'IssueInstant="2026-08-14T12:00:00Z"' in xml


def test_force_authn_is_off_unless_asked_for(sp: ServiceProvider) -> None:
    normal = build_authn_request(
        sp=sp, idp_sso_url=IDP_SSO_URL, request_id="id-x", issued_at=ISSUED_AT
    )
    forced = build_authn_request(
        sp=sp, idp_sso_url=IDP_SSO_URL, request_id="id-x", issued_at=ISSUED_AT, force_authn=True
    )

    assert "ForceAuthn" not in normal
    assert 'ForceAuthn="true"' in forced


def test_the_compressed_request_uses_raw_deflate() -> None:
    """The spec wants raw deflate, no zlib header. Send a normal zlib stream and
    the provider can't read it, and says so unhelpfully."""
    encoded = deflate_and_encode("<hello/>")

    raw = base64.b64decode(encoded)
    assert zlib.decompress(raw, -zlib.MAX_WBITS) == b"<hello/>"

    with pytest.raises(zlib.error):
        zlib.decompress(raw)


def test_the_redirect_carries_the_request_and_the_relay_state(sp: ServiceProvider) -> None:
    xml = build_authn_request(
        sp=sp, idp_sso_url=IDP_SSO_URL, request_id="id-x", issued_at=ISSUED_AT
    )
    relay_state = "token-123"

    url = login_redirect_url(
        idp_sso_url=IDP_SSO_URL, authn_request_xml=xml, relay_state=relay_state
    )

    query = parse_qs(urlparse(url).query)
    assert query["RelayState"] == [relay_state]
    round_tripped = zlib.decompress(
        base64.b64decode(query["SAMLRequest"][0]), -zlib.MAX_WBITS
    ).decode()
    assert round_tripped == xml


def test_the_redirect_appends_to_an_sso_url_that_already_has_a_query() -> None:
    """Some providers hand you a URL with parameters already on it."""
    url = login_redirect_url(
        idp_sso_url="https://idp.example/sso?tenant=abc",
        authn_request_xml="<a/>",
        relay_state="r",
    )

    query = parse_qs(urlparse(url).query)
    assert query["tenant"] == ["abc"]
    assert "SAMLRequest" in query


@pytest.mark.parametrize("path", ["/", "/users", "/groups/123", "/audit?filter=x"])
def test_allows_returning_to_a_path_on_this_site(path: str) -> None:
    assert is_safe_return_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        "users",
        "",
    ],
)
def test_refuses_to_send_people_off_this_site_after_login(path: str) -> None:
    """Otherwise a login link could send people somewhere else afterwards, and it
    would look completely legitimate because it starts at a real login page.

    The "//evil.example" case is the one that gets missed: it looks like a path but
    browsers read it as another host.
    """
    assert not is_safe_return_path(path)
