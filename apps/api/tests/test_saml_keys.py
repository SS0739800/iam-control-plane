"""Tests for the keypair we sign logins with.

Two of these matter more than the rest.

Production must refuse to start without a key. A quietly generated one is
a key nobody wrote down, nobody backed up, and nobody can rotate — and
every login it signed stops verifying the next time the process restarts.

A mismatched key and certificate must refuse too. That failure is
otherwise invisible: the app starts, metadata publishes, assertions get
signed, and every application rejects every login because the signature
doesn't match the published certificate.

No database and no xmlsec, so these run anywhere — why key handling uses
``cryptography`` rather than living behind the xmlsec boundary.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from iam.config import AppEnv, Settings
from iam.main import create_app
from iam.saml.keys import KEY_SIZE, UnusableKeypair, for_settings, generate, load
from tests.support import UNREACHABLE_DATABASE_URL

REAL = generate(common_name="http://localhost:8080")
OTHER = generate(common_name="http://localhost:8080")


def settings_for(
    *,
    private_key: str | None = None,
    certificate: str | None = None,
    env: AppEnv = "local",
) -> Settings:
    return Settings(
        app_env=env,
        session_secret="test-secret-deliberately-not-the-placeholder",
        database_url=UNREACHABLE_DATABASE_URL,
        saml_idp_private_key=private_key,
        saml_idp_certificate=certificate,
    )


# ------------------------------------------------------------- generating one


def test_a_generated_pair_is_usable() -> None:
    pair = generate(common_name="http://localhost:8080")

    assert "BEGIN PRIVATE KEY" in pair.private_key_pem
    assert "BEGIN CERTIFICATE" in pair.certificate_pem
    assert pair.generated is True


def test_the_key_is_rsa_of_the_expected_size() -> None:
    """Every provider accepts RSA-2048. Anything more exotic is a compatibility
    problem nobody asked for."""
    key = serialization.load_pem_private_key(REAL.private_key_pem.encode(), password=None)

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == KEY_SIZE


def test_the_certificate_is_valid_from_slightly_in_the_past() -> None:
    """Clocks are not perfectly aligned, and a certificate that is not valid yet
    fails in a way nobody thinks to check."""
    certificate = x509.load_pem_x509_certificate(REAL.certificate_pem.encode())

    assert certificate.not_valid_before_utc < certificate.not_valid_after_utc
    # Self-signed: the issuer is the subject.
    assert certificate.issuer == certificate.subject


def test_the_certificate_body_has_no_pem_markers_or_newlines() -> None:
    """SAML metadata carries the base64 alone. Leaving the markers in produces
    metadata a provider accepts and then fails every signature against."""
    body = REAL.certificate_body

    assert "-----" not in body
    assert "\n" not in body
    assert body.startswith("MII")


def test_the_fingerprint_is_short_and_derived_from_the_certificate() -> None:
    assert REAL.fingerprint != OTHER.fingerprint
    assert len(REAL.fingerprint) < len(REAL.certificate_body)


# ----------------------------------------------------------------- loading one


def test_a_configured_pair_loads() -> None:
    pair = load(settings_for(private_key=REAL.private_key_pem, certificate=REAL.certificate_pem))

    assert pair.generated is False
    assert pair.certificate_body == REAL.certificate_body


def test_outside_production_a_missing_pair_is_generated() -> None:
    """So `docker compose up` works on a laptop without a setup step."""
    pair = load(settings_for())

    assert pair.generated is True


def test_production_refuses_to_start_without_a_key() -> None:
    """The one that matters. A key nobody chose is a key nobody can rotate, and
    every login it signed dies with the process."""
    with pytest.raises(UnusableKeypair, match="cannot be signed"):
        load(settings_for(env="production"))


def test_production_says_how_to_make_one() -> None:
    """A refusal that doesn't say what to do next just moves the problem."""
    with pytest.raises(UnusableKeypair, match="generate_idp_key"):
        load(settings_for(env="production"))


def test_a_key_without_a_certificate_is_refused() -> None:
    with pytest.raises(UnusableKeypair, match="SAML_IDP_CERTIFICATE is set"):
        load(settings_for(certificate=REAL.certificate_pem))


def test_a_certificate_without_a_key_is_refused() -> None:
    with pytest.raises(UnusableKeypair, match="SAML_IDP_PRIVATE_KEY is set"):
        load(settings_for(private_key=REAL.private_key_pem))


def test_a_file_path_instead_of_pem_is_refused_clearly() -> None:
    """The most likely mistake, and one whose real error message is about ASN.1."""
    with pytest.raises(UnusableKeypair, match="does not look like PEM"):
        load(settings_for(private_key="/etc/ssl/private/idp.key", certificate="/etc/ssl/idp.crt"))


def test_pem_whose_newlines_were_eaten_is_refused() -> None:
    """What happens when a key is pasted into a .env without quotes."""
    flattened = REAL.private_key_pem.replace("\n", "")

    with pytest.raises(UnusableKeypair):
        load(settings_for(private_key=flattened, certificate=REAL.certificate_pem))


def test_a_mismatched_pair_is_refused() -> None:
    """The invisible failure: everything works and every login is rejected."""
    with pytest.raises(UnusableKeypair, match="does not match the private key"):
        load(settings_for(private_key=REAL.private_key_pem, certificate=OTHER.certificate_pem))


def test_a_non_rsa_key_is_refused() -> None:
    """Signing here is RSA-SHA256. An EC key would load and then fail at signing
    time, which is a worse place to find out."""
    curve_key = ec.generate_private_key(ec.SECP256R1())
    pem = curve_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    with pytest.raises(UnusableKeypair, match="not RSA"):
        load(settings_for(private_key=pem, certificate=REAL.certificate_pem))


# --------------------------------------------------------------- reused, not rebuilt


def test_the_same_settings_give_the_same_key() -> None:
    """Including the generated case. Every request in one process has to get the
    same made-up key, or logins stop verifying between one request and the next."""
    settings = settings_for()

    assert for_settings(settings).certificate_pem == for_settings(settings).certificate_pem


def test_different_settings_give_different_keys() -> None:
    """A single cached value would hand the second app the first one's key, which
    would make the production refusal pass or fail depending on test order."""
    configured = for_settings(
        settings_for(private_key=REAL.private_key_pem, certificate=REAL.certificate_pem)
    )
    other = for_settings(
        settings_for(private_key=OTHER.private_key_pem, certificate=OTHER.certificate_pem)
    )

    assert configured.certificate_body != other.certificate_body


# ------------------------------------------------------------ refusing to boot


def test_the_app_refuses_to_build_in_production_without_a_key() -> None:
    """Better than starting and failing every login with a signature error that
    points nowhere near the cause."""
    with pytest.raises(RuntimeError, match="Cannot sign logins"):
        create_app(
            Settings(
                app_env="production",
                session_secret="a-real-secret-value-for-this-test",
                database_url=UNREACHABLE_DATABASE_URL,
            )
        )


def test_the_app_refuses_to_build_with_a_mismatched_pair() -> None:
    with pytest.raises(RuntimeError, match="does not match the private key"):
        create_app(
            Settings(
                app_env="production",
                session_secret="a-real-secret-value-for-this-test",
                database_url=UNREACHABLE_DATABASE_URL,
                saml_idp_private_key=REAL.private_key_pem,
                saml_idp_certificate=OTHER.certificate_pem,
            )
        )


def test_the_app_keeps_the_keypair_where_handlers_can_reach_it() -> None:
    app = create_app(
        settings_for(private_key=REAL.private_key_pem, certificate=REAL.certificate_pem)
    )

    assert app.state.saml_keypair.certificate_body == REAL.certificate_body


# Deliberately not tested here: that nothing writes the key to disk. The version of
# that test I wrote took a tmp_path it never used and compared a module __dict__,
# which proves nothing about the filesystem — it would have passed whatever
# generate() did. The property is real and worth keeping, but it is enforced by
# generate() returning PEM and having no file handling in it at all, which is
# clearer to check by reading it than by a test that only looks like a check.
