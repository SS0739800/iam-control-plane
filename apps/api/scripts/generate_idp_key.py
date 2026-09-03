"""Generate the keypair this system signs logins with.

    python -m scripts.generate_idp_key

Prints a private key and a certificate as PEM, ready to paste into .env. Writes
nothing to disk, so the key only ever exists in the one place you choose to
keep it.
"""

from __future__ import annotations

import argparse
import sys

from iam.config import get_settings
from iam.saml.keys import CERTIFICATE_YEARS, generate


def _quote_for_env(pem: str) -> str:
    """PEM as a single .env value.

    Quoted because a multi-line value without quotes only keeps its first line,
    producing a key that loads but fails to parse with a confusing ASN.1 error.
    """
    return '"' + pem.strip() + '"'


def main() -> int:
    # Windows pipes stdout as cp1252, which can't encode the ellipsis in the
    # fingerprint and raises UnicodeEncodeError without this.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--common-name",
        default=None,
        help="Name to put in the certificate. Defaults to BASE_URL, which is what "
        "identifies this system to the applications that trust it.",
    )
    parser.add_argument(
        "--years",
        type=int,
        default=CERTIFICATE_YEARS,
        help=f"How long the certificate lasts. Default {CERTIFICATE_YEARS}.",
    )
    args = parser.parse_args()

    common_name = args.common_name or get_settings().base_url
    pair = generate(common_name=common_name, valid_for_years=args.years)

    print()
    print(f"Signing keypair for {common_name}, valid {args.years} years.")
    print(f"Certificate fingerprint: {pair.fingerprint}")
    print()
    print("Add both of these to .env. Keep the quotes — the value is multi-line, and")
    print("without them only the first line survives.")
    print()
    print(f"SAML_IDP_PRIVATE_KEY={_quote_for_env(pair.private_key_pem)}")
    print()
    print(f"SAML_IDP_CERTIFICATE={_quote_for_env(pair.certificate_pem)}")
    print()
    print("Then:")
    print("  - .env is gitignored. Keep it that way.")
    print("  - This key can issue a login as anybody, for every application that")
    print("    trusts this system. Treat losing it as an incident.")
    print("  - Every application registered against the old certificate has to be")
    print("    given the new one, so rotating is a coordinated change, not a quiet one.")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
