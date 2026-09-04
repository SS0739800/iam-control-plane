# 7. Outbound requests go only where an admin configured, and never to link-local

- **Status:** accepted
- **Date:** 2026-08-19

## Context

[ADR 0006](0006-paste-metadata.md) says this system never fetches a
URL somebody gives it. The reasoning was that our server sits inside the compose
network next to Postgres, Redis and authentik, and in P7 inside a hosting provider's
network with a metadata service on a link-local address that hands out credentials
to anything that asks. An administrator's browser can reach none of that. Handing
the inside a URL from the outside is the vulnerability, and the privilege of
whoever supplied it does not change what the server can reach.

P6 makes us a SCIM client. Provisioning accounts outward *is* our server making HTTP
requests to an address a person typed in. So either ADR 0006 was wrong, or this is
different, and it is worth being precise about which — because "we already do it
over there" is how a rule stops meaning anything.

Three things genuinely differ.

**It is the feature, not a convenience.** Fetching metadata was a nicety that saved
one copy and paste; the alternative cost nothing. Pushing accounts to a downstream
system cannot be done without an outbound request. There is no version of outbound
provisioning that does not make one.

**It is configured, not supplied.** A metadata URL would arrive in a request body
and be fetched immediately, once, by whoever sent it. A provisioning target is a row
somebody created on purpose, visible in the console, in the audit log, and
reviewable long afterwards. The person who typed it and the person who triggers a
push are usually not the same person, and the row is the evidence.

**It is inside by design.** The downstream we most want to provision into runs in the
same compose network — `http://hrms:8000`. Refusing private addresses outright, which
is the standard SSRF mitigation, would refuse the main use case.

That last point is the awkward one, because it means the usual answer does not apply.

## Decision

Outbound requests are allowed only to a registered provisioning target, and the
target's address is checked when it is registered rather than at every push.

**Link-local is refused always, in every environment.** `169.254.0.0/16` and
`fe80::/10`. Nothing legitimate is a SCIM server there, and it is where the cloud
metadata services live — the single most valuable thing an SSRF reaches. This is not
configurable and does not relax outside production.

**Private and loopback addresses are refused in production, allowed elsewhere.**
`http://hrms:8000` is the point of local development, and in production a
provisioning target on a private address is much more likely to be a mistake or an
attack than an intention. An operator who genuinely needs one sets
`ALLOW_PRIVATE_PROVISIONING_TARGETS`, which is long to type and shows
up on the target's page.

**HTTPS is required in production.** A bearer token that writes to somebody else's
directory should not cross a network in the clear. Plain HTTP is allowed locally,
where the network is a bridge inside one machine.

**Redirects are not followed.** A target that answers 302 gets a failure, not a
second request somewhere else. Following one would move the destination from the
reviewed row to whatever the far end said, which is the problem coming back in
by another door.

Checking at registration instead of per-push is a trade. It means a
hostname that later resolves somewhere private is not caught, and the alternative —
resolving before every request — is slower, still racy, and gives a false sense of
having solved it. The row being reviewable is the real control.

## Consequences

- ADR 0006 stands unchanged. It is about fetching a URL from a request; this is about
  a configured integration. The distinction is "who chose the address, and when",
  and it is the distinction the checks above enforce.
- The metadata service is unreachable from this system regardless of configuration,
  which is the outcome worth having.
- Local development works with plain HTTP to a container name, and production cannot
  be configured that way by accident.
- A target's page shows what was allowed and why, so somebody reviewing later can see
  that a private address was a decision rather than an oversight.
- A downstream behind a redirect needs its real address registered. That is a small
  amount of friction in exchange for the destination staying the one that was
  reviewed.
