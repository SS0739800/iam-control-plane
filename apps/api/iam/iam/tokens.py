"""Issuing and storing bearer secrets, in one place.

Two things in this system hand out a long random string and later have to
recognise it: the session cookie a person gets after logging in, and the token an
identity provider sends on every SCIM request. They are different features with
the same problem, and the same answer.

**We store the hash, never the secret.** Someone who reads the table cannot use
what they find. That is worth having for a session cookie and worth more for a
SCIM token, which is a long-lived credential with write access to the directory.

**Plain SHA-256, not bcrypt or argon2.** Slow hashing exists to make guessing
human-chosen passwords expensive. These are 32 random bytes from the system's
own source — there is nothing to guess — so a slow hash would only add work to
every request while buying nothing. This is the one place that reasoning is
written down, which is why both callers come here rather than each hashing their
own.

**Compared in constant time.** Two hashes of the same length compared with `==`
return faster on an earlier mismatch. That leaks very little, and comparing
properly costs nothing, so there is no reason to take the trade.

Why this is not in iam/security/
--------------------------------

It was, and it caused a circular import. ``iam/security/__init__.py`` re-exports
the actor resolution, which reaches the access grants, which reach the leaver
flow, which reaches the session store — which needs this. Importing one leaf
function pulled in that whole graph and the loop closed.

Nothing here is a policy decision. It is randomness and a hash: a primitive that
several parts of the system happen to share. Keeping primitives outside the
packages that make decisions is what stops this happening again.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32
"""How much randomness goes into a token.

256 bits. Guessing one is not a thing that happens, which is what lets us skip
rate-limiting the token check itself.
"""


def new_token() -> str:
    """A fresh secret to hand out. This is the only moment it exists in readable form."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """What we store instead of the secret itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(candidate_hash: str, stored_hash: str) -> bool:
    """Compare two token hashes without leaking where they diverge."""
    return hmac.compare_digest(candidate_hash, stored_hash)
