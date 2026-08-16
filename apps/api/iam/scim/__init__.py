"""SCIM 2.0, the inbound half: an identity provider pushing accounts to us.

SAML answers "is this person who they say they are, right now". SCIM answers
"who exists, and what are they". They are different questions and they arrive
through different doors — a login carries one person and happens when they turn
up, while SCIM carries the whole directory and happens whether anyone logs in or
not.

That difference is the reason P2's just-in-time creation is a fallback rather
than the plan. Somebody created by logging in exists only from their first login;
somebody created by SCIM exists from the moment HR added them, and disappears
from our side the moment they're removed upstream, without waiting for them to
come back and prove it.

What's in here:

constants.py   the URNs and paths the spec fixes, in one place
filters.py     the subset of the filter grammar we accept, and why it's a subset
errors.py      SCIM's own error shape, which is not FastAPI's
mapping.py     turning our rows into SCIM resources and back

The pydantic models live in iam/schemas/scim.py with the rest of the schemas.
None of this needs xmlsec or XML — SCIM is JSON — so unlike the SAML half, all
of it runs and is tested anywhere.
"""

from __future__ import annotations
