"""Tests for reading a provider's metadata document.

One test per way a document can be shaped or malformed. The documents here are
built to match what authentik, Okta and Entra actually publish, ugly namespace
prefixes and all — a tidied-up invention would pass while the real thing failed.

No xmlsec and no database, so these run anywhere. That is the point of parsing
metadata with the standard library; see the module docstring on iam/saml/metadata.py.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from iam.saml.metadata import (
    MAX_METADATA_BYTES,
    UnreadableMetadata,
    certificate_fingerprint,
    read_idp_metadata,
    read_sp_metadata,
)

ENTITY_ID = "https://authentik.demo.local/application/saml/iam/sso/binding/redirect/"
SSO_REDIRECT = "https://authentik.demo.local/application/saml/iam/sso/binding/redirect/"
SSO_POST = "https://authentik.demo.local/application/saml/iam/sso/binding/post/"
SLO_REDIRECT = "https://authentik.demo.local/application/saml/iam/slo/binding/redirect/"

# Not real certificates, but real base64, so the fingerprint is computed the way
# it is for a genuine one rather than falling back to hashing text. Long enough to
# exercise the PEM line wrapping too.
CERT_BODY = base64.b64encode(b"fake-signing-key-for-tests" + bytes(range(200))).decode()
OTHER_CERT_BODY = base64.b64encode(b"fake-encryption-key" + bytes(range(50, 250))).decode()


def _as_pem_block(body: str) -> str:
    """The certificate the way it comes back out of read_idp_metadata."""
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"


def key_descriptor(cert_body: str, use: str | None = "signing") -> str:
    use_attribute = f' use="{use}"' if use else ""
    return (
        f"    <md:KeyDescriptor{use_attribute}>\n"
        '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
        "        <ds:X509Data>\n"
        f"          <ds:X509Certificate>{cert_body}</ds:X509Certificate>\n"
        "        </ds:X509Data>\n"
        "      </ds:KeyInfo>\n"
        "    </md:KeyDescriptor>\n"
    )


def authentik_metadata(
    *,
    entity_id: str | None = ENTITY_ID,
    keys: str | None = None,
    sso: str | None = None,
    slo: bool = True,
    descriptor: str = "IDPSSODescriptor",
) -> str:
    """Metadata shaped the way authentik publishes it."""
    entity_attribute = f' entityID="{entity_id}"' if entity_id is not None else ""
    key_block = key_descriptor(CERT_BODY) if keys is None else keys
    sso_block = (
        sso
        if sso is not None
        else (
            "    <md:SingleSignOnService"
            ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            f' Location="{SSO_REDIRECT}"/>\n'
            "    <md:SingleSignOnService"
            ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            f' Location="{SSO_POST}"/>\n'
        )
    )
    slo_block = (
        "    <md:SingleLogoutService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
        f' Location="{SLO_REDIRECT}"/>\n'
        if slo
        else ""
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
        f"{entity_attribute}>\n"
        f"  <md:{descriptor}"
        ' WantAuthnRequestsSigned="false"'
        ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f"{key_block}"
        f"{slo_block}"
        "    <md:NameIDFormat>"
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        "</md:NameIDFormat>\n"
        f"{sso_block}"
        f"  </md:{descriptor}>\n"
        "</md:EntityDescriptor>\n"
    )


# ------------------------------------------------------------- the happy path


def test_reads_the_four_things_we_need() -> None:
    metadata = read_idp_metadata(authentik_metadata())

    assert metadata.entity_id == ENTITY_ID
    assert metadata.sso_url == SSO_REDIRECT
    assert metadata.slo_url == SLO_REDIRECT
    assert CERT_BODY in metadata.signing_cert.replace("\n", "")


def test_the_certificate_comes_back_as_a_pem_block() -> None:
    """python3-saml wants PEM. Handing it the bare base64 out of the document works
    often enough to be misleading and then fails on one provider."""
    cert = read_idp_metadata(authentik_metadata()).signing_cert

    assert cert.startswith("-----BEGIN CERTIFICATE-----\n")
    assert cert.endswith("\n-----END CERTIFICATE-----")

    body_lines = cert.splitlines()[1:-1]
    assert all(len(line) <= 64 for line in body_lines)
    assert "".join(body_lines) == CERT_BODY


def test_whitespace_in_the_certificate_is_cleaned_up() -> None:
    """Providers wrap the base64 however their template felt like wrapping it."""
    messy = f"\n        {CERT_BODY[:40]}\n        {CERT_BODY[40:]}\n      "

    cert = read_idp_metadata(authentik_metadata(keys=key_descriptor(messy))).signing_cert

    assert "".join(cert.splitlines()[1:-1]) == CERT_BODY


def test_prefers_the_redirect_binding_for_signing_in() -> None:
    """That's the one we send people over: the request goes in a query string."""
    assert read_idp_metadata(authentik_metadata()).sso_url == SSO_REDIRECT


def test_takes_the_post_binding_when_that_is_all_there_is() -> None:
    """Unusual but valid, so it beats refusing to register the provider."""
    only_post = (
        "    <md:SingleSignOnService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
        f' Location="{SSO_POST}"/>\n'
    )

    assert read_idp_metadata(authentik_metadata(sso=only_post)).sso_url == SSO_POST


def test_a_provider_with_no_logout_address_is_fine() -> None:
    """Plenty of providers don't offer one, and it isn't needed to log in."""
    metadata = read_idp_metadata(authentik_metadata(slo=False))

    assert metadata.slo_url is None
    assert metadata.sso_url == SSO_REDIRECT


def test_reads_metadata_wrapped_in_an_entities_descriptor() -> None:
    """What a federation hands out: several providers in one file."""
    inner = authentik_metadata().split("\n", 1)[1]
    wrapped = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">\n'
        f"{inner}"
        "</md:EntitiesDescriptor>\n"
    )

    metadata = read_idp_metadata(wrapped)

    assert metadata.entity_id == ENTITY_ID
    assert metadata.sso_url == SSO_REDIRECT


# ------------------------------------------------------------- the fingerprint


def test_two_different_certificates_have_different_fingerprints() -> None:
    """The test that caught the bug this function used to have.

    An earlier version took the first and last few characters of the PEM block,
    which every certificate on earth shares — they all start with
    "-----BEGIN CERTIFICATE-----". Every fingerprint came out identical, so a
    certificate rotation looked like nothing had changed.
    """
    mine = certificate_fingerprint(_as_pem_block(CERT_BODY))
    theirs = certificate_fingerprint(_as_pem_block(OTHER_CERT_BODY))

    assert mine != theirs


def test_the_fingerprint_ignores_how_the_certificate_was_wrapped() -> None:
    """PEM block or bare base64, wrapped at 64 characters or not at all: the same
    certificate has to fingerprint the same, or comparing two of them is useless."""
    bare = certificate_fingerprint(CERT_BODY)
    wrapped = certificate_fingerprint(_as_pem_block(CERT_BODY))
    from_metadata = read_idp_metadata(authentik_metadata()).certificate_fingerprint

    assert bare == wrapped == from_metadata


def test_the_fingerprint_is_the_one_other_tools_print() -> None:
    """Same value as `openssl x509 -fingerprint -sha256`, so an administrator can
    compare ours against what the provider's own console shows."""
    expected = hashlib.sha256(base64.b64decode(CERT_BODY)).hexdigest().upper()

    fingerprint = certificate_fingerprint(_as_pem_block(CERT_BODY))

    assert fingerprint.replace(":", "") == expected
    assert fingerprint.count(":") == 31


def test_a_certificate_that_is_not_base64_still_fingerprints() -> None:
    """It won't match openssl, because there's no DER to hash. It must still be
    stable and still differ between certificates, rather than raising over a value
    we were only ever going to display."""
    first = certificate_fingerprint("not-valid-base64-!!")
    again = certificate_fingerprint("not-valid-base64-!!")
    other = certificate_fingerprint("also-not-base64-!!")

    assert first == again
    assert first != other


# ------------------------------------------------------- picking the right key


def test_takes_the_signing_key_not_the_encryption_one() -> None:
    """A provider can publish both. Taking whichever came first would eventually
    pick the encryption key and fail every login with a signature error that points
    nowhere near the cause."""
    both = key_descriptor(OTHER_CERT_BODY, use="encryption") + key_descriptor(
        CERT_BODY, use="signing"
    )

    cert = read_idp_metadata(authentik_metadata(keys=both)).signing_cert

    assert CERT_BODY in cert.replace("\n", "")
    assert OTHER_CERT_BODY not in cert.replace("\n", "")


def test_a_key_with_no_stated_use_is_accepted() -> None:
    """No `use` attribute means the key is good for anything, signing included."""
    cert = read_idp_metadata(
        authentik_metadata(keys=key_descriptor(CERT_BODY, use=None))
    ).signing_cert

    assert CERT_BODY in cert.replace("\n", "")


def test_an_encryption_only_document_is_refused() -> None:
    """Nothing to check a login against, so registering it would be pointless."""
    with pytest.raises(UnreadableMetadata, match="no signing certificate"):
        read_idp_metadata(
            authentik_metadata(keys=key_descriptor(OTHER_CERT_BODY, use="encryption"))
        )


def test_a_document_with_no_certificate_at_all_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="no signing certificate"):
        read_idp_metadata(authentik_metadata(keys=""))


def test_an_empty_certificate_element_is_refused() -> None:
    """A provider mid-setup publishes this, and it must not become an empty PEM
    block that fails much later with a confusing error."""
    with pytest.raises(UnreadableMetadata, match="no signing certificate"):
        read_idp_metadata(authentik_metadata(keys=key_descriptor("   ")))


# ------------------------------------------------------- documents we refuse


def test_an_empty_document_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="empty"):
        read_idp_metadata("   \n  ")


def test_something_that_is_not_xml_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="not valid XML"):
        read_idp_metadata("this is not xml at all")


def test_a_document_with_a_doctype_is_refused() -> None:
    """A DOCTYPE is what an entity expansion attack needs. Real metadata never has
    one, so refusing outright is a rule with no edge cases."""
    billion_laughs = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE lolz [\n"
        '  <!ENTITY lol "lol">\n'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        "]>\n"
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">'
        "&lol2;</md:EntityDescriptor>"
    )

    with pytest.raises(UnreadableMetadata, match="DOCTYPE"):
        read_idp_metadata(billion_laughs)


def test_an_absurdly_large_document_is_refused_before_parsing() -> None:
    with pytest.raises(UnreadableMetadata, match="larger than"):
        read_idp_metadata("<md:EntityDescriptor>" + "x" * (MAX_METADATA_BYTES + 1))


def test_application_metadata_says_so_rather_than_failing_vaguely() -> None:
    """Pasting in the metadata for the other side of the connection is an easy
    mistake, and a confusing one to debug if it's reported as a generic failure."""
    with pytest.raises(UnreadableMetadata, match="describes an application"):
        read_idp_metadata(authentik_metadata(descriptor="SPSSODescriptor"))


def test_a_document_that_is_not_saml_metadata_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="IDPSSODescriptor"):
        read_idp_metadata("<something-else/>")


def test_a_document_with_no_entity_id_is_refused() -> None:
    """Without it there's no way to tell which provider a login came from, which is
    one of the checks every login has to pass."""
    with pytest.raises(UnreadableMetadata, match="entityID"):
        read_idp_metadata(authentik_metadata(entity_id=None))


def test_a_document_with_no_sign_in_address_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="sign-in address"):
        read_idp_metadata(authentik_metadata(sso=""))


# ==================================================== an application's metadata

SP_ENTITY_ID = "https://expenses.demo.local/saml/metadata"
ACS_POST = "https://expenses.demo.local/saml/acs"
ACS_REDIRECT = "https://expenses.demo.local/saml/acs-redirect"
SP_SLO = "https://expenses.demo.local/saml/slo"


def application_metadata(
    *,
    entity_id: str | None = SP_ENTITY_ID,
    keys: str = "",
    acs: str | None = None,
    slo: bool = True,
    want_assertions_signed: str = "true",
    descriptor: str = "SPSSODescriptor",
) -> str:
    """Metadata shaped the way an application publishes it.

    The default carries no certificate, because that is the common case: most
    applications never sign anything they send us.
    """
    entity_attribute = f' entityID="{entity_id}"' if entity_id is not None else ""
    acs_block = (
        acs
        if acs is not None
        else (
            "    <md:AssertionConsumerService"
            ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            f' Location="{ACS_POST}" index="0" isDefault="true"/>\n'
        )
    )
    slo_block = (
        "    <md:SingleLogoutService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
        f' Location="{SP_SLO}"/>\n'
        if slo
        else ""
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
        f"{entity_attribute}>\n"
        f"  <md:{descriptor}"
        f' AuthnRequestsSigned="false"'
        f' WantAssertionsSigned="{want_assertions_signed}"'
        ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f"{keys}"
        f"{slo_block}"
        f"{acs_block}"
        f"  </md:{descriptor}>\n"
        "</md:EntityDescriptor>\n"
    )


def test_reads_what_registering_an_application_needs() -> None:
    read = read_sp_metadata(application_metadata())

    assert read.entity_id == SP_ENTITY_ID
    assert read.acs_url == ACS_POST
    assert read.slo_url == SP_SLO


def test_the_assertion_consumer_prefers_the_post_binding() -> None:
    """The one place the binding preference flips, and it matters.

    An assertion is delivered as a form POST — it is far too long for a query
    string. Taking the redirect address would send every login somewhere that
    cannot read it.
    """
    both = (
        "    <md:AssertionConsumerService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
        f' Location="{ACS_REDIRECT}" index="1"/>\n'
        "    <md:AssertionConsumerService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
        f' Location="{ACS_POST}" index="0" isDefault="true"/>\n'
    )

    assert read_sp_metadata(application_metadata(acs=both)).acs_url == ACS_POST


def test_a_redirect_only_consumer_is_still_taken() -> None:
    """Unusual, and refusing it outright would be worse than registering it and
    letting the login fail with something specific."""
    only_redirect = (
        "    <md:AssertionConsumerService"
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
        f' Location="{ACS_REDIRECT}" index="0"/>\n'
    )

    assert read_sp_metadata(application_metadata(acs=only_redirect)).acs_url == ACS_REDIRECT


def test_an_application_with_no_certificate_is_fine() -> None:
    """The asymmetry with a provider, and the common case.

    A provider's certificate is compulsory: checking a signature against it is the
    whole basis of trusting a login. An application's is only needed if it signs what
    it sends us, and most do not.
    """
    read = read_sp_metadata(application_metadata(keys=""))

    assert read.signing_cert is None
    assert read.entity_id == SP_ENTITY_ID


def test_an_application_certificate_is_read_when_there_is_one() -> None:
    read = read_sp_metadata(application_metadata(keys=key_descriptor(CERT_BODY)))

    assert read.signing_cert is not None
    assert CERT_BODY in read.signing_cert.replace("\n", "")


def test_an_application_with_no_logout_address_is_fine() -> None:
    read = read_sp_metadata(application_metadata(slo=False))

    assert read.slo_url is None
    assert read.acs_url == ACS_POST


def test_want_assertions_signed_is_read() -> None:
    assert read_sp_metadata(application_metadata()).want_assertions_signed is True
    assert (
        read_sp_metadata(
            application_metadata(want_assertions_signed="false")
        ).want_assertions_signed
        is False
    )


def test_an_application_asking_for_less_still_gets_a_signed_assertion() -> None:
    """The flag is read for completeness and does not change what we do.

    We sign the assertion either way, because signing only the response wrapper
    leaves the claims swappable. An application asking for less gets more.
    """
    read = read_sp_metadata(application_metadata(want_assertions_signed="false"))

    assert read.want_assertions_signed is False
    # Nothing in the parsed result can switch signing off — there is no such field.
    assert not hasattr(read, "sign_assertion")


def test_provider_metadata_pasted_here_says_so() -> None:
    """The mirror of the message on the other side. Pasting the wrong side's document
    in is an easy mistake and a confusing one to debug as a generic failure."""
    with pytest.raises(UnreadableMetadata, match="describes an identity provider"):
        read_sp_metadata(authentik_metadata())


def test_a_document_with_no_sp_descriptor_is_refused() -> None:
    with pytest.raises(UnreadableMetadata, match="SPSSODescriptor"):
        read_sp_metadata("<something-else/>")


def test_an_application_with_no_consumer_address_is_refused() -> None:
    """Nowhere to send a login, so there is nothing to register."""
    with pytest.raises(UnreadableMetadata, match="assertion consumer"):
        read_sp_metadata(application_metadata(acs=""))


def test_an_application_with_no_entity_id_is_refused() -> None:
    """The entity id is how an AuthnRequest is matched to a registered application,
    so without one there is nothing to look up."""
    with pytest.raises(UnreadableMetadata, match="entityID"):
        read_sp_metadata(application_metadata(entity_id=None))


def test_application_metadata_wrapped_in_an_entities_descriptor() -> None:
    inner = application_metadata().split("\n", 1)[1]
    wrapped = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">\n'
        f"{inner}"
        "</md:EntitiesDescriptor>\n"
    )

    assert read_sp_metadata(wrapped).entity_id == SP_ENTITY_ID


def test_a_doctype_is_refused_here_too() -> None:
    """Same rule as the provider side: a DOCTYPE is what an entity expansion attack
    needs, and real metadata never has one."""
    with pytest.raises(UnreadableMetadata, match="DOCTYPE"):
        read_sp_metadata(
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE x [<!ENTITY a "b">]>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>'
        )


def test_our_own_service_provider_metadata_is_readable() -> None:
    """The tightest available check that this reader is real.

    sp.py publishes our metadata as a service provider, written in P2 against the
    spec. If this reader can read that, the two agree — and if it cannot, an
    application publishing normal metadata probably cannot be registered either.
    """
    from iam.saml.sp import ServiceProvider

    ours = ServiceProvider.from_base_url("http://localhost:8080")

    read = read_sp_metadata(ours.metadata_xml())

    assert read.entity_id == ours.entity_id
    assert read.acs_url == ours.acs_url
    assert read.slo_url == ours.slo_url
