"""Encrypting the secrets we have to be able to read back.

Three kinds of secret live in this system, and they get three different treatments.
Which one applies is decided by a single question: does anything here ever need the
original value again?

**Session cookies and inbound SCIM tokens: hashed.** We only ever need to recognise
a value somebody presents, never to produce it. So only the hash is stored, and a
database dump tells an attacker nothing usable. See iam/security/tokens.py.

**The SAML signing key: not in the database at all.** It has to be usable, and it is
catastrophic — it mints logins for anybody, at every application that trusts us. So
it comes from the environment and production refuses to start without it. See
iam/saml/keys.py.

**Outbound SCIM tokens: encrypted here.** This is the third case and it needs its
own answer, because neither of the others fits.

They have to be usable — we send them to a downstream system on every push — so
hashing is out. But there can be many of them, one per system we provision into, and
adding one is an ordinary administrative act. Putting them in the environment would
mean a variable per target and a redeploy to onboard a downstream, which is the kind
of friction that ends with somebody pasting a token into a comment instead.

So they go in the database, encrypted, with the key from the environment. That is
strictly weaker than the signing key's treatment and the difference is deliberate:
what an outbound token buys an attacker is write access to *somebody else's*
directory, which is serious and is not the ability to become anybody here.

What this does and does not protect against
-------------------------------------------

It protects against a database dump, a backup on a laptop, and read-only SQL
injection — the realistic ways a table leaks without the application leaking with it.

It does not protect against somebody who already has the running process, because
that process must be able to decrypt to do its job. Nothing can fix that, and
claiming otherwise would be the more dangerous mistake.
"""

from __future__ import annotations

import base64
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from iam.config import Settings

logger = logging.getLogger(__name__)

DERIVATION_INFO = b"iam.outbound-scim-tokens.v1"
"""Ties a derived key to this one purpose.

Part of HKDF's contract: the same input secret with a different info string gives an
unrelated key. So a key derived here can never coincide with one derived somewhere
else from the same secret, even by accident.

Versioned because changing it changes every derived key, which would make stored
tokens undecryptable. If that ever has to happen it should be a visible decision
with a migration, not a quiet edit.
"""


class CannotDecrypt(Exception):
    """A stored secret could not be read back.

    Almost always the encryption key changing rather than corruption — a rotated
    SESSION_SECRET with no SCIM_ENCRYPTION_KEY set, most likely. The message says so,
    because "invalid token" on its own sends people looking at the wrong thing.
    """


def _fernet(settings: Settings) -> Fernet:
    """The cipher, from an explicit key or derived from the session secret.

    An explicit SCIM_ENCRYPTION_KEY is preferred and is what production should use,
    because it can then be rotated independently of everything else.

    Deriving from SESSION_SECRET is the fallback, and it is a real convenience rather
    than a shortcut: it means a laptop needs no extra setup and the key is stable
    across restarts, which an in-memory key could never be — ciphertext outlives the
    process that wrote it.

    The cost is a coupling worth stating plainly: with no explicit key, rotating
    SESSION_SECRET makes every stored token unreadable. They would each need
    re-entering. That is survivable and it is why the explicit key exists.
    """
    explicit = settings.scim_encryption_key
    if explicit:
        try:
            return Fernet(explicit.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise CannotDecrypt(
                "SCIM_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=DERIVATION_INFO,
    ).derive(settings.session_secret.encode("utf-8"))

    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(value: str, settings: Settings) -> str:
    """Encrypt a secret for storage.

    Returns text rather than bytes so it goes in an ordinary column and shows up
    legibly — as obvious ciphertext — to anybody looking at the table.
    """
    return _fernet(settings).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(stored: str, settings: Settings) -> str:
    """Read a stored secret back.

    Raises:
        CannotDecrypt: The key has changed, or the value is not something we wrote.
    """
    try:
        return _fernet(settings).decrypt(stored.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CannotDecrypt(
            "That stored secret could not be decrypted. The encryption key has "
            "almost certainly changed — either SCIM_ENCRYPTION_KEY was set or "
            "rotated, or SESSION_SECRET was rotated while it was being used to "
            "derive the key. The token has to be entered again."
        ) from exc


def looks_encrypted(value: str) -> bool:
    """Whether a value is one of ours, without needing the key.

    For a migration or a health check that wants to tell an encrypted column from a
    plaintext one. Fernet tokens are urlsafe-base64 and start with a version byte of
    0x80, which encodes as 'gA'.
    """
    return value.startswith("gA") and len(value) > 40
