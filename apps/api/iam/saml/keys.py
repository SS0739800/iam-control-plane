"""The keypair we sign assertions with.

This is the most dangerous secret in the system. The session cookie secret lets
somebody forge a session; this key lets somebody mint a login for anybody, for
any application that trusts us, and it verifies correctly every time. There's
no way to tell a forged assertion from a real one after the fact.

It is not in the database. Every other secret here (session tokens, SCIM
tokens) is stored hashed, since a hash is useless to whoever reads it. This key
has to be usable as-is, so storing it next to the user table would mean a
database dump or one SQL injection is enough to impersonate the entire
company. It comes from the environment instead, which in compose comes from a
gitignored file.

Production refuses to start without one, same as SESSION_SECRET: no default,
no key generated quietly at boot. If a key just appears with no record of who
generated it, nobody can rotate it on purpose, and every login it signed stops
verifying the next time the process restarts.

Outside production there's a loud fallback: it generates a keypair in memory,
logs a warning that logins signed with it stop verifying on restart, and never
writes it anywhere. Fine for `docker compose up` on a laptop, wrong anywhere
else.

Nothing here needs xmlsec. Generating, loading and checking a keypair is
``cryptography``, which installs on every platform, so this is all testable on
a laptop. Only the actual signing in signer.py needs the container.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from iam.config import Settings

logger = logging.getLogger(__name__)

KEY_SIZE = 2048
"""RSA key length. 2048 is the floor every provider accepts; 4096 is slower to
generate and buys nothing anybody has asked for."""

CERTIFICATE_YEARS = 5
"""How long a generated certificate lasts.

Long, since this certificate isn't proving our identity to a browser, it's just
a container for a public key handed to each application at registration.
Expiry would mean every one of those applications needs updating on the same
day, so a short lifetime buys nothing and just schedules an outage.
"""

PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_KEY_HEADERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")


class UnusableKeypair(Exception):
    """The configured key or certificate can't be used, and the message says why."""


@dataclass(frozen=True, slots=True)
class Keypair:
    """The private key we sign with, and the certificate we publish.

    Both as PEM text, because that is what xmlsec and every provider's
    registration form want. The parsed objects are only needed to check the two
    actually belong together.
    """

    private_key_pem: str
    certificate_pem: str
    generated: bool = False
    """True when this was made up at boot because none was configured. Only
    happens outside production."""

    @property
    def certificate_body(self) -> str:
        """The base64 between the PEM markers, which is what goes in metadata.

        SAML metadata carries the certificate without its header, footer, or
        line breaks. Getting this wrong produces metadata a provider accepts
        and then fails every signature against.
        """
        lines = [
            line.strip()
            for line in self.certificate_pem.strip().splitlines()
            if line.strip() and not line.startswith("-----")
        ]
        return "".join(lines)

    @property
    def fingerprint(self) -> str:
        """Short identifier for the certificate, for showing a human.

        Not used for anything security-relevant, just so "the key changed" is
        visible at a glance instead of diffing two blocks of base64.
        """
        body = self.certificate_body
        return f"{body[:16]}…{body[-16:]}" if len(body) > 32 else body


def generate(*, common_name: str, valid_for_years: int = CERTIFICATE_YEARS) -> Keypair:
    """Make a fresh keypair and a self-signed certificate for it.

    Self-signed is correct here, not a shortcut. Nothing checks this against a
    chain of trust; each application is told this exact certificate at
    registration and compares future signatures against that one. A
    certificate authority would add a step without changing what gets
    verified.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        # Issuer is the subject: that's what self-signed means.
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # A minute in the past, so slight clock skew doesn't make it "not valid yet".
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365 * valid_for_years))
        .sign(key, hashes.SHA256())
    )

    return Keypair(
        private_key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii"),
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        generated=True,
    )


def _check_they_belong_together(private_key_pem: str, certificate_pem: str) -> None:
    """Confirm the certificate's public key matches the private key.

    Catches somebody rotating one and not the other. Without this check
    everything looks fine at startup, but every application rejects every
    login since the signature doesn't match the published certificate.
    Checking here turns that confusing outage into a refusal to boot.

    Raises:
        UnusableKeypair: They don't match, or either one can't be parsed.
    """
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    except (ValueError, TypeError) as exc:
        raise UnusableKeypair(f"the private key could not be read: {exc}") from exc

    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except ValueError as exc:
        raise UnusableKeypair(f"the certificate could not be read: {exc}") from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise UnusableKeypair(
            "the private key is not RSA. SAML signing here uses RSA-SHA256, which is "
            "what every provider accepts."
        )

    if key.public_key().public_numbers() != certificate.public_key().public_numbers():  # type: ignore[union-attr]
        raise UnusableKeypair(
            "the certificate does not match the private key. Something rotated one "
            "and not the other — every application would reject every login."
        )


def _looks_like_pem(value: str, headers: tuple[str, ...]) -> bool:
    return any(header in value for header in headers)


def load(settings: Settings) -> Keypair:
    """The keypair to sign with, from settings.

    Raises:
        UnusableKeypair: In production, when none is configured, or when the pair
            doesn't hold up. Outside production a missing pair is replaced by a
            generated one and warned about.
    """
    private_key = (settings.saml_idp_private_key or "").strip()
    certificate = (settings.saml_idp_certificate or "").strip()

    if not private_key and not certificate:
        if settings.is_production:
            raise UnusableKeypair(
                "SAML_IDP_PRIVATE_KEY and SAML_IDP_CERTIFICATE are not set, so logins "
                "cannot be signed. Generate a pair with: python -m scripts.generate_idp_key"
            )

        made = generate(common_name=settings.base_url)
        logger.warning(
            "saml.idp_key_generated",
            extra={
                "detail": (
                    "No signing keypair configured, so one was generated in memory. "
                    "It is not saved anywhere, so every login signed with it stops "
                    "verifying when this process restarts, and any application "
                    "registered against it has to be updated. Fine for local work; "
                    "run scripts/generate_idp_key.py and set SAML_IDP_PRIVATE_KEY "
                    "and SAML_IDP_CERTIFICATE for anything else."
                ),
                "fingerprint": made.fingerprint,
            },
        )
        return made

    # One without the other is always a mistake, so give a specific message here
    # instead of leaving somebody to stare at a signature error.
    if not private_key:
        raise UnusableKeypair("SAML_IDP_CERTIFICATE is set but SAML_IDP_PRIVATE_KEY is not.")
    if not certificate:
        raise UnusableKeypair("SAML_IDP_PRIVATE_KEY is set but SAML_IDP_CERTIFICATE is not.")

    # Usually means a .env file holding a file path, or PEM whose newlines got
    # eaten by whatever pasted it.
    if not _looks_like_pem(private_key, PEM_KEY_HEADERS):
        raise UnusableKeypair(
            "SAML_IDP_PRIVATE_KEY does not look like PEM. It should be the whole key "
            "including the BEGIN PRIVATE KEY line, not a path to a file."
        )
    if not _looks_like_pem(certificate, (PEM_CERT_HEADER,)):
        raise UnusableKeypair(
            "SAML_IDP_CERTIFICATE does not look like PEM. It should be the whole "
            "certificate including the BEGIN CERTIFICATE line."
        )

    _check_they_belong_together(private_key, certificate)

    return Keypair(private_key_pem=private_key, certificate_pem=certificate, generated=False)


_loaded: dict[tuple[str, str, bool, str], Keypair] = {}


def for_settings(settings: Settings) -> Keypair:
    """The keypair for these settings, loaded once and reused.

    Cached because parsing PEM and comparing public numbers is real work for an
    answer that only changes on restart.

    Keyed on the settings that decide it, not cached as a single global value.
    Otherwise a test that builds a second app with a different key would get
    back whichever key was loaded first, and the production refusal test would
    pass or fail depending on what ran before it.

    The generated-in-memory case is cached too, so every request in one
    process gets the same made-up key and logins keep verifying until the
    process stops.
    """
    cache_key = (
        settings.saml_idp_private_key or "",
        settings.saml_idp_certificate or "",
        settings.is_production,
        settings.base_url,
    )

    found = _loaded.get(cache_key)
    if found is None:
        found = load(settings)
        _loaded[cache_key] = found
    return found
