# 6. Register providers from pasted metadata, never from a URL we fetch

- **Status:** accepted
- **Date:** 2026-08-14

## Context

Registering an identity provider means recording four things: what it calls
itself, where to send people to log in, where to send them to log out, and the
certificate every login from it must be signed with. All four live in a metadata
document the provider publishes, usually at a URL.

So the obvious feature is a form with one field in it: paste the metadata URL,
and we fetch it and fill in the rest. Every commercial IAM product offers this,
because it is genuinely the nicest version of the flow.

It also means an HTTP request made by our server to an address someone typed.

That is server-side request forgery, and the usual reassurance — "only an
administrator can do it" — does not hold up here, for two reasons.

The first is that our server can reach things the administrator cannot. It sits
inside the compose network, next to Postgres, next to Redis, next to authentik's
admin API. In P7 it sits inside a hosting provider's network with a metadata
service on a link-local address that hands out credentials to anything that asks.
An administrator's browser can reach none of that. Their browser is on the
outside; our server is on the inside. Handing the inside a URL from the outside
is the vulnerability, and the privilege level of the person supplying it
does not change what the server can reach.

The second is that "an administrator asked for it" and "an administrator was
told to ask for it" look identical from here. Setting up SSO is exactly the sort
of task where somebody follows a link from a vendor's onboarding email and pastes
what it says to paste.

## Decision

Metadata is pasted in as XML. The server never fetches it.

`POST /api/identity-providers` takes the document itself. Getting hold of it is
the operator's job, on the operator's machine, with the operator's network
access:

```bash
curl -sS https://idp.example/metadata > idp.xml
```

`iam/saml/metadata.py` parses that document with the standard library rather than
lxml, which is a separate decision made for a different reason and explained in
that file: unlike a login response, metadata is not attacker-supplied, so it
needs no cryptography, and using the standard library means provider registration
is tested on any machine instead of only in the container.

## Consequences

- There is no code path where our server makes an outbound request to an address
  a user chose. Not restricted to an allowlist, not filtered for private address
  ranges, not there at all. That is a much easier property to keep true than a
  blocklist is, and it stays true as the network around us changes.
- Registering a provider is two steps instead of one. It is also two steps in
  which the operator sees exactly what they are trusting, which for the single
  most consequential write in the system is not obviously worse.
- No HTTP client in the runtime dependencies for this.
- The API takes the certificate from the document rather than from a separate
  field, so the common mistake — pasting an encryption certificate where the
  signing one belongs — cannot happen. `_signing_cert` picks the key marked for
  signing.
- If a provider rotates its certificate, someone has to paste the new metadata.
  A background refresh job would need the fetch this decision rules out, so the
  answer there is a reminder rather than a poll.
