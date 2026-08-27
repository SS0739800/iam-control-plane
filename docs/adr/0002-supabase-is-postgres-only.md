# 2. Supabase is a Postgres host, nothing else

- **Status:** accepted, amended by [ADR 0009](0009-neon-hosts-postgres.md)
- **Date:** 2026-08-10

> **The vendor changed; nothing else did.** Postgres is hosted by Neon, not
> Supabase, because Supabase's free tier manages one database per project and allows
> two projects, and this deployment needs two. See
> [ADR 0009](0009-neon-hosts-postgres.md).
>
> Every rule below still applies. Neon has a Data API, an auth service and storage of
> its own, so this is the same set of features to leave switched off, under different
> names — including verifying the Data API is off before the first table exists. The
> move bought a quota, not a smaller attack surface.
>
> Read "Supabase" below as "the database host".

## Context

The database is Supabase, chosen for a free managed Postgres with a usable SQL
editor. Supabase also ships an authentication service (GoTrue), row-level
security conventions, and an auto-generated REST API over every table
(PostgREST).

All three are actively harmful here.

**Auth.** This project *is* an identity system. Adopting Supabase Auth would mean
two user tables, two session models, and two sources of truth about who someone
is — and it would hollow out the thing being demonstrated. Nobody is impressed by
SAML assertions that get handed to someone else's session layer.

**RLS.** The API connects as a single role and enforces authorization in the
application layer, where the entitlement model lives. Per-row policies would
duplicate that logic in a second language, and they fight Alembic.

**PostgREST.** This is the dangerous one. Supabase exposes tables at `/rest/v1`,
and the `anon` key is public by design. With RLS off, anyone holding the project
URL and that key can read the user table and the audit log. On a project about
access control, that is the worst possible finding.

## Decision

Use Supabase as managed Postgres and nothing else.

- **Supabase Auth: unused.** Sessions are server-side rows in our schema, keyed
  to a `HttpOnly` cookie the API issues after validating a SAML assertion.
- **RLS: off.** Authorization is a concern of the application layer.
- **Data API: disabled** in project settings, before the first table exists.
  Verified by requesting `/rest/v1/users` with the anon key and confirming it
  returns nothing.

The schema stays portable Postgres — no Supabase-specific extensions — so the
provider is replaceable. Local development runs plain `postgres:16`, which keeps
that honest.

## Consequences

- More code: session handling, password-less login, and RBAC are ours to write.
  That code *is* the deliverable, so this is not a cost.
- The Supabase dashboard remains useful for inspection and ad-hoc SQL.
- Migrating to RDS or Neon later is a connection-string change.
- Supabase will warn that RLS is disabled on public tables. That warning targets
  people exposing the database to browsers directly. We are not, because the Data
  API is off — but the warning will recur and should not be "fixed" by enabling
  RLS without revisiting this record.
