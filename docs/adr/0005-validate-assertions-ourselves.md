# 5. Use a library for the signature, write the other checks ourselves

- **Status:** accepted
- **Date:** 2026-08-13

## Context

When a login comes back from the identity provider, we get an XML document that
claims a particular person just authenticated. Trusting it means checking a list
of things:

1. The signature is real and made with the key we expect
2. The signature covers the part we're reading, not some other part
3. It came from an provider we know about
4. It was meant for us, not for a different application
5. It hasn't expired, and isn't dated in the future
6. It was sent to our address
7. It's answering a login request we actually made
8. We haven't seen this exact one before
9. The provider says the login succeeded

Skip any one of these and the whole thing is decoration. Skip number 4 and an
assertion issued for some other app gets you in here. Skip number 8 and anyone
who captures one login can replay it forever.

There's a library, `python3-saml`, that does all of this in one call. Using it
that way would be fine engineering and a bad fit for this project, for two
reasons.

The first is that the checks would be invisible. This is a portfolio project
about identity, and "I called a function" and "I know why each of those nine
things matters" look identical from outside. There'd be nothing to show and
nothing to talk about.

The second is that we want a record of each check for the login inspector. A
single pass/fail tells you nothing when a login mysteriously stops working
against a new provider. Nine named results tell you it was the clock.

## Decision

Split it. Use the library for the cryptography, do the logic ourselves.

**The library verifies the signature.** Rolling your own XML signature
verification is a genuinely bad idea — canonicalisation alone has a long history
of vulnerabilities, and getting it subtly wrong means accepting forged logins
while all the tests pass. `python3-saml` wraps `xmlsec`, which wraps OpenSSL.
That stays.

**We do the rest.** Issuer, audience, timing with a clock-skew allowance,
destination, the reply-to-our-request check, the replay check, and the status
code are all straightforward comparisons with no cryptography in them. Each one
is its own function that returns a named result.

**Every result gets recorded.** The audit entry for a login carries all nine, so
the console can show them as a checklist beside the decoded assertion. That's the
inspector.

## Consequences

- Someone reading this repo can see the checks, and I can talk about any of them.
- A login that fails against a new provider says which check failed, instead of
  "invalid assertion".
- We own the correctness of eight comparisons. They're covered by tests that feed
  in bad assertions, one broken thing at a time.
- More code than one library call. That's the trade.
- The signature check is not ours and shouldn't become ours. If it ever looks
  tempting to replace, don't.
- `xmlsec` won't install on Windows, so anything touching this runs in the
  container or in CI. See ADR 0004.
