"""Generate the keypair this system signs logins with.

    python -m scripts.generate_idp_key

Prints a private key and a certificate as PEM, ready to paste into .env. Writes
nothing: the whole point is that the key exists in exactly one place you chose, and
a script that helpfully saved it to disk would be creating a copy you did not decide
to keep.

The private key is not printed with any ceremony, because ceremony encourages
scrolling past. Read the warning instead — this key can mint a login for anybody, in
any application that trusts this system, and every one of those logins verifies
correctly.
"""

from __future__ import annotations

import argparse
import sys

from iam.config import get_settings
from iam.saml.keys import CERTIFICATE_YEARS, generate


def _quote_for_env(pem: str) -> str:
    """PEM as a single .env value.

    A multi-line value has to be quoted or the file only carries its first line —
    which produces a key that loads, fails to parse, and reports something unhelpful
    about ASN.1. The quotes and the real newlines inside them are what make it work.
    """
    return '"' + pem.strip() + '"'


def main() -> int:
    # Windows uses the locale encoding for a piped stdout, which is cp1252 here, and
    # the fingerprint contains an ellipsis. Without this the script either mangles
    # its own output or raises UnicodeEncodeError while printing a key somebody now
    # has to generate again.
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
