# 9. Neon hosts Postgres, not Supabase

- **Status:** accepted
- **Date:** 2026-08-26
- **Amends:** [ADR 0002](0002-postgres-only.md)

## Context

ADR 0002 chose Supabase for a free managed Postgres and spent most of its length
explaining how to switch off everything else Supabase ships — Auth, RLS
conventions, and the auto-generated REST API over every table. The dangerous one
was PostgREST: the `anon` key is public by design, so with the Data API enabled and
RLS off, anyone holding the project URL could read the user table and the audit log.

Deploying for real turned up a limit that was not visible when the decision was
made. **Supabase's free tier allows two active projects, and it manages exactly one
database per project.** This deployment needs two databases: ours, and authentik's,
because authentik runs its own migrations and would rewrite our schema if pointed at
the same one.

Two databases therefore means two Supabase projects, and the account already had two
in use for other things. Even freeing one slot leaves the deployment a database
short. The free tier cannot host this project at all once authentik is included.

Worth noting the shape of the constraint: it is Supabase-specific. Local development
has always run two databases on one server — `infra/db/init/01-create-databases.sh`
creates authentik's role and database next to ours, with the comment "We need two
databases on one server: ours and authentik's." Ordinary Postgres does this without
comment. Supabase is what makes it awkward.

ADR 0002 anticipated this move and left the door open: "The schema
stays portable Postgres — no Supabase-specific extensions — so the provider is
replaceable," and "Migrating to RDS or Neon later is a connection-string change."
That held. Nothing in the schema, the models, or the migrations needed touching.

## Decision

**Neon hosts Postgres.** One project, two databases, arranged the way local already
is.

**ADR 0002 applies unchanged, to a different vendor.** An earlier draft of this
record claimed Neon was "Postgres and nothing else", with no REST surface over the
tables, and used that to drop the Data API verification step from the runbook. That
was wrong: Neon's connection dialog has **Data API**, **Auth** and **Storage** tabs.
The claim was asserted rather than checked, and it removed the one step guarding
against the worst finding this project could have.

So every rule in ADR 0002 carries over:

- **The Data API must be off, and verified off.** Not assumed, and not trusted to a
  default — checked with a request, before the first table exists. A REST endpoint
  over `users` and `audit_events` reachable with a public key is the finding that
  ends a project about access control, and which vendor is hosting makes no
  difference to it.
- **The auth service is unused.** Sessions remain server-side rows keyed to a
  `HttpOnly` cookie. This project *is* an identity system; delegating identity to
  the database host would hollow out the thing being demonstrated.
- **RLS stays off**, for the reason ADR 0002 gave: authorization belongs in the
  application layer where the entitlement model lives.

The lesson worth keeping: the reason to move was a quota, not a security
improvement. Treating a vendor change as though it retired a threat is how the
threat comes back.

What carries over unchanged is the pooling distinction, because it is a property of
transaction-mode pooling rather than of any vendor. Neon spells it differently:

| Which                          | Host                | Used for        |
| ------------------------------ | ------------------- | --------------- |
| Pooled (PgBouncer, transaction) | `...-pooler...`     | the running app |
| Direct                          | no `-pooler`        | migrations only |

`DB_POOLER_MODE=transaction` still switches `iam/db.py` to `NullPool` with both
statement caches off, and `ALEMBIC_DATABASE_URL` still exists because schema changes
cannot go through transaction-mode pooling.

### The libpq parameter trap

Neon hands out URLs ending `?sslmode=require&channel_binding=require`. Both are
libpq's spellings, which psql and psycopg understand and **asyncpg does not** — its
`connect()` takes neither name, has no `**kwargs` to absorb the difference, and
SQLAlchemy passes query parameters through to the driver untranslated.

Pasting the URL from the dashboard therefore raises `TypeError: connect() got an
unexpected keyword argument 'sslmode'` on the first query. And because the readiness
endpoint hides exception messages, since they can contain the connection
string — production would report `{"detail": "TypeError"}` and nothing else.

`iam/config.py` handles both, differently, because they are different problems:

- **`sslmode` is renamed** to `ssl`. asyncpg accepts the same values (`require`,
  `verify-full`, and so on), so only the key changes.
- **`channel_binding` is dropped.** asyncpg has no equivalent. That is a real if
  small loss — it asks for SCRAM channel binding, which defends against an attacker
  holding a valid certificate for the wrong host — but asyncpg cannot honour the
  request either way, so the choice is between connecting without it and not
  connecting. `ssl=require` still means the connection is encrypted.

Anything else is left alone. Silently discarding query parameters we do not
recognise would throw away what somebody actually asked for, without saying so.

Fixing only `sslmode` would have moved the failure rather than removed it, which is
what nearly happened: the first version of this handled `sslmode`, and
`channel_binding` was found only because a screenshot of the real dashboard had both.
None of this is Neon-specific — every managed Postgres hands out libpq spellings.

## Consequences

- **A connection-string change, as advertised.** No schema, model, or migration
  edits. ADR 0002's portability clause earned its keep.
- **Nothing less to remember.** The Data API verification step stays in the runbook.
  The move bought a second database, not a smaller attack surface.
- **Backups are Neon's.** Supabase and Neon both provide them on the free tier;
  Fly's cheap Postgres would not have, which is why it lost.
- **Two databases, one project**, matching local. authentik gets its own database
  and its own role, exactly as `01-create-databases.sh` does locally.
- **ADR 0002 is not withdrawn**, and not weakened. Its reasoning about why an
  identity system must not delegate identity to its database host is still the
  reasoning, and it applies to Neon for the same reasons it applied to Supabase.
  Only the vendor changed.
- Moving again stays cheap. Nothing added here is Neon-specific either; the
  `sslmode` rewrite helps on any provider.
