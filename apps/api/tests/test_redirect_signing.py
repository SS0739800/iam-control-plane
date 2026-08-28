"""Signing the logout request, the way the redirect binding wants it.

Why this exists
---------------

Single logout silently did nothing against Okta. Our session ended, Okta's did not,
and the next login walked straight back in without asking for a password — which is
the opposite of what somebody pressing sign out believes they have done. Okta refuses
an unsigned LogoutRequest, and the note in sp.py had said so since P2: "a provider
that does insist needs a key of ours, which arrives in P5". P5 arrived; this is the
work that was deferred.

The signing is not XML signing
------------------------------

That is the whole difficulty. The redirect binding signs the *query string*, not the
document, and the rule is exact: build ``SAMLRequest=…&RelayState=…&SigAlg=…`` in that
order with each value URL-encoded, sign those bytes, append ``Signature=``. Not the
decoded XML, not a different parameter order, not the string after somebody
re-encodes it. Every one of those produces a signature that verifies against nothing,
and the provider says only "invalid signature".

So these tests verify the way a provider does — with the public key, over the exact
octets from the URL — rather than checking that a signature is merely present. A test
that only asserted "Signature is in the query string" would have passed against every
one of the wrong implementations above.

No xmlsec here, so these run everywhere. That is a happy consequence of it being
query-string signing: it is the one part of SAML that needs no native library.
"""

from __future__ import annotations

import base64
import datetime as dt
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from iam.saml.sp import RSA_SHA256, ServiceProvider, build_logout_request, redirect_binding_url

NOW = dt.datetime(2026, 8, 27, 12, 0, tzinfo=dt.UTC)


@pytest.fixture(scope="module")
def keypair() -> tuple[str, rsa.RSAPublicKey]:
    """A throwaway key. Generated rather than fixed, so the test cannot pass by
    accidentally comparing against a recorded signature."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return pem, key.public_key()


def a_request() -> str:
    return build_logout_request(
        sp=ServiceProvider.from_base_url("https://console.test"),
        idp_slo_url="https://idp.test/slo",
        request_id="id-abc",
        name_id="ada@demo.local",
        issued_at=NOW,
        session_index="session-1",
    )


def verify_like_a_provider(url: str, public_key: rsa.RSAPublicKey) -> bool:
    """Check the signature the way the receiving end does.

    Two subtleties, and the second one caught a mistake in this helper rather than in
    the code under test.

    The signed octets are used exactly as they arrived, not parsed and re-encoded.
    Rebuilding them would hide the bug where we sign one string and send another.

    And the signature covers only the SAML parameters — SAMLRequest or SAMLResponse,
    RelayState, SigAlg — not whatever query string the provider's own endpoint already
    carried. The first version of this took everything before "&Signature=", which
    swept the endpoint's own parameters in and failed only for providers whose SLO
    address has a query string. Those exist, which is why there is a test for it.
    """
    query = urlparse(url).query
    marker = "&Signature="
    assert marker in query, "no signature on the URL"
    everything, _, signature_part = query.partition(marker)

    for start in ("SAMLRequest=", "SAMLResponse="):
        if start in everything:
            signed_octets = everything[everything.index(start) :]
            break
    else:
        raise AssertionError("no SAML message in the query")

    signature = base64.b64decode(parse_qs(f"Signature={signature_part}")["Signature"][0])
    try:
        public_key.verify(
            signature, signed_octets.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )
    except Exception:
        return False
    return True


# ----------------------------------------------------------------- signing


def test_an_unsigned_url_carries_no_signature(keypair: tuple[str, rsa.RSAPublicKey]) -> None:
    """Still the behaviour when no key is configured, which is what local development
    without a keypair does."""
    url = redirect_binding_url("https://idp.test/slo", saml_request=a_request())

    assert "Signature=" not in url
    assert "SigAlg=" not in url


def test_a_signed_url_verifies_against_our_public_key(
    keypair: tuple[str, rsa.RSAPublicKey],
) -> None:
    """The test that would have caught every wrong version of this."""
    private_pem, public_key = keypair

    url = redirect_binding_url(
        "https://idp.test/slo", saml_request=a_request(), private_key_pem=private_pem
    )

    assert verify_like_a_provider(url, public_key)


def test_the_algorithm_is_named_in_the_query(keypair: tuple[str, rsa.RSAPublicKey]) -> None:
    """SigAlg tells the provider what to verify with. Leaving it out means a
    signature nobody knows how to check."""
    private_pem, _ = keypair
    url = redirect_binding_url(
        "https://idp.test/slo", saml_request=a_request(), private_key_pem=private_pem
    )

    assert parse_qs(urlparse(url).query)["SigAlg"] == [RSA_SHA256]


def test_relay_state_is_inside_the_signature(keypair: tuple[str, rsa.RSAPublicKey]) -> None:
    """RelayState travels in the clear, so it has to be signed or it can be swapped in
    flight. Its position matters too — the specification fixes the order."""
    private_pem, public_key = keypair

    url = redirect_binding_url(
        "https://idp.test/slo",
        saml_request=a_request(),
        relay_state="opaque-token",
        private_key_pem=private_pem,
    )

    assert "RelayState=opaque-token" in url
    assert verify_like_a_provider(url, public_key)


def test_tampering_with_the_message_breaks_the_signature(
    keypair: tuple[str, rsa.RSAPublicKey],
) -> None:
    """The point of signing at all. If this passes with a changed message then the
    signature is over the wrong thing."""
    private_pem, public_key = keypair
    url = redirect_binding_url(
        "https://idp.test/slo", saml_request=a_request(), private_key_pem=private_pem
    )

    tampered = url.replace("SAMLRequest=", "SAMLRequest=x", 1)

    assert not verify_like_a_provider(tampered, public_key)


def test_tampering_with_relay_state_breaks_it_too(
    keypair: tuple[str, rsa.RSAPublicKey],
) -> None:
    private_pem, public_key = keypair
    url = redirect_binding_url(
        "https://idp.test/slo",
        saml_request=a_request(),
        relay_state="mine",
        private_key_pem=private_pem,
    )

    assert not verify_like_a_provider(
        url.replace("RelayState=mine", "RelayState=theirs"), public_key
    )


def test_a_response_can_be_signed_as_well_as_a_request(
    keypair: tuple[str, rsa.RSAPublicKey],
) -> None:
    """Logout runs in both directions: a provider can start it, and then we are the
    one answering. That answer needs signing for the same reason."""
    private_pem, public_key = keypair

    url = redirect_binding_url(
        "https://idp.test/slo", saml_response="<samlp:LogoutResponse/>", private_key_pem=private_pem
    )

    assert "SAMLResponse=" in url
    assert verify_like_a_provider(url, public_key)


def test_the_endpoint_keeps_its_own_query_parameters(
    keypair: tuple[str, rsa.RSAPublicKey],
) -> None:
    """Some providers hand out an SLO address that already has a query string, and
    joining with "?" a second time produces a URL that goes nowhere."""
    private_pem, public_key = keypair

    url = redirect_binding_url(
        "https://idp.test/slo?tenant=acme",
        saml_request=a_request(),
        private_key_pem=private_pem,
    )

    assert "tenant=acme" in url
    assert url.count("?") == 1
    assert verify_like_a_provider(url, public_key)


# ------------------------------------------------ publishing the certificate


def test_metadata_publishes_the_certificate_when_there_is_one() -> None:
    """A signature the provider cannot verify is refused just as firmly as no
    signature, so the certificate and the signing are one feature."""
    sp = ServiceProvider.from_base_url("https://console.test", signing_certificate="MIIBFAKE")

    xml = sp.metadata_xml()

    assert 'use="signing"' in xml
    assert "MIIBFAKE" in xml


def test_metadata_says_nothing_when_there_is_no_key() -> None:
    """An empty KeyDescriptor is a document some providers reject and others accept
    and then fail against. Saying nothing at least means "this one does not sign"."""
    xml = ServiceProvider.from_base_url("https://console.test").metadata_xml()

    assert "KeyDescriptor" not in xml


def test_the_metadata_is_still_well_formed_with_a_certificate() -> None:
    """Hand-built XML, so this is worth checking rather than assuming.

    The KeyDescriptor is assembled from string fragments like the rest of the
    document, and an unbalanced tag would be published to every provider that
    registers against us.
    """
    from xml.etree import ElementTree

    sp = ServiceProvider.from_base_url("https://console.test", signing_certificate="MIIBFAKE")

    # Our own output, not untrusted input — same reasoning as iam/saml/metadata.py.
    ElementTree.fromstring(sp.metadata_xml())  # noqa: S314
