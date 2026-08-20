# Deploying

Three Fly apps and a Supabase database.

| App            | What                                             | Public |
| -------------- | ------------------------------------------------ | ------ |
| `iam-console`  | The API and the frontend, one process            | yes    |
| `iam-hrms`     | The downstream we provision into                 | yes    |
| `iam-authentik`| The identity provider, server and worker         | yes    |

The console is one app serving both halves — see
[ADR 0008](adr/0008-one-server-serves-both-halves-in-production.md). The HRMS is its
own app because it is meant to be a genuinely separate system. authentik is its own
app because it is somebody else's software.

Read [ADR 0002](adr/0002-supabase-is-postgres-only.md) before touching Supabase.
There is one step there that has to happen **before the first table exists**.

---

## 0. Before anything

```bash
# flyctl, if it isn't there yet
curl -L https://fly.io/install.sh | sh
fly auth login
```

You need: a Fly account with a card on file (the free allowance still asks for one),
and a Supabase project.

---

## 1. Supabase

**Do this first, before running any migration.**

1. Create the project. Note the region — put the Fly apps near it, because every
   request the console serves does at least one query and a cross-continent round
   trip shows up immediately.
2. **Settings → API → disable the Data API.** Not later. The `anon` key is public by
   design, and with the Data API on and RLS off, anyone with the project URL and
   that key can read the user table and the audit log. On a project about access
   control that is the worst possible finding. ADR 0002 covers why RLS is not the
   fix here.
3. Verify it is really off, rather than trusting the toggle:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' \
     -H "apikey: <anon-key>" \
     "https://<project>.supabase.co/rest/v1/users"
   # want: 404 (or anything that is not 200 with a body)
   ```

4. Collect two connection strings from **Settings → Database**. They are different
   and both are needed:

   | Which                       | Port | Used for            |
   | --------------------------- | ---- | ------------------- |
   | Transaction pooler          | 6543 | the running app     |
   | Direct connection           | 5432 | migrations only     |

   Migrations cannot run through the transaction pooler — schema changes and
   transaction-mode pooling do not mix. That is why `ALEMBIC_DATABASE_URL` exists
   separately from `DATABASE_URL`.

   Rewrite both to asyncpg form:

   ```
   postgresql+asyncpg://postgres.<ref>:<password>@<host>:6543/postgres
   postgresql+asyncpg://postgres.<ref>:<password>@<host>:5432/postgres
   ```

---

## 2. The console

```bash
fly apps create iam-console
```

### Secrets

Generate them rather than inventing them.

```bash
# The session secret. Production refuses to start if this is still the placeholder.
fly secrets set SESSION_SECRET="$(openssl rand -hex 32)" -a iam-console

# Both database URLs from step 1.
fly secrets set \
  DATABASE_URL="postgresql+asyncpg://postgres.<ref>:<pw>@<host>:6543/postgres" \
  ALEMBIC_DATABASE_URL="postgresql+asyncpg://postgres.<ref>:<pw>@<host>:5432/postgres" \
  -a iam-console
```

### The SAML signing key

The most dangerous secret here, and the one thing that must not be regenerated
casually: every application registered against us holds the matching certificate,
and replacing the key means re-registering all of them.

```bash
cd apps/api && python -m scripts.generate_idp_key
```

That prints both values. Set them as secrets — note the quotes, because the value is
multi-line and without them only the first line survives:

```bash
fly secrets set SAML_IDP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----" -a iam-console

fly secrets set SAML_IDP_CERTIFICATE="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----" -a iam-console
```

Production **will not start** without these. That is deliberate: outside production
a throwaway pair is generated in memory, and a key that changes on every restart
would silently invalidate every assertion we ever signed.

Keep a copy somewhere you would keep a private key. Fly will not show it to you
again.

### Deploy

```bash
fly deploy                    # from the repository root; reads ./fly.toml
```

The build compiles `xmlsec` from source and takes several minutes the first time
([ADR 0004](adr/0004-build-xmlsec-from-source.md)). It is also the step most likely
to fail, and it fails loudly — the image asserts `xmlsec.init()` works in both the
builder and the runtime stage, and that the frontend bundle arrived.

### Migrate

The image does not migrate on boot, on purpose. Two machines starting at once would
run Alembic twice, and a migration is not something to race.

```bash
fly ssh console -a iam-console -C "python -m alembic upgrade head"
```

### Check it

```bash
fly open -a iam-console
```

Then, and this is the list that matters rather than "the site loads":

```bash
B=https://iam-console.fly.dev

curl -s $B/api/health                       # env should say "production"
curl -s $B/api/health/ready                 # database: ok
curl -s -o /dev/null -w '%{http_code}\n' $B/           # 200, the frontend
curl -s -o /dev/null -w '%{http_code}\n' $B/users      # 200 — a deep link
curl -s -o /dev/null -w '%{http_code}\n' $B/api/nonsense  # 404, NOT html
curl -s $B/api/me                           # 401 — the dev actor must be off
curl -s -o /dev/null -w '%{http_code}\n' $B/saml/metadata  # 200
```

The deep link is the one people skip. `/users` is a React route with no file behind
it, and locally the Vite dev server invents `index.html` for unknown paths — so this
works in development whether or not anybody made it work in production. ADR 0008
names it as the honest cost of serving the bundle from the API process.

`/api/me` returning 401 is the other one. If it returns a user, `APP_ENV` is not
production and the development actor is answering requests — which is impersonation,
not authentication, on a public URL.

---

## 3. The HRMS

```bash
cd apps/hrms
fly apps create iam-hrms
fly volumes create hrms_data --size 1 -a iam-hrms
fly secrets set HRMS_SCIM_TOKEN="$(openssl rand -hex 32)" -a iam-hrms
fly deploy
```

Keep that token. It goes into the console in the next step, and neither side will
show it to you again.

The volume matters: without it every deploy empties the HRMS, and somebody
demonstrating the leaver flow would find the joiner had vanished.

### Register it as a provisioning target

In the console, **Provisioning out → Register a target**:

| Field         | Value                                            |
| ------------- | ------------------------------------------------ |
| Application   | HRMS                                             |
| Its SCIM root | `http://iam-hrms.internal:8000/scim/v2`          |
| Token         | the `HRMS_SCIM_TOKEN` from above                 |

`.internal` is Fly's private network — the request never leaves the organisation.
That is a private address over plain HTTP, which
[ADR 0007](adr/0007-outbound-requests-go-only-where-an-admin-configured.md) refuses
in production unless `ALLOW_PRIVATE_PROVISIONING_TARGETS` is set. It is set in
`fly.toml`, on purpose, and the target will record the concession so it reads as a
decision rather than an oversight.

Then **Check it answers**, then **Sync now**. The first sync pushes everybody
entitled to the application and runs inside the request — around forty seconds
against a seeded directory of 1,200. There is no background worker; that is a stated
limitation, not a surprise.

---

## 4. authentik

The heaviest part of this deploy, and the part to cut first if the bill matters. It
needs a server, a worker, Redis, and its own database — separate from ours, because
it owns its schema.

```bash
fly apps create iam-authentik
fly volumes create authentik_media --size 1 -a iam-authentik

# Redis. Upstash via Fly, or any Redis you already have.
fly redis create                      # note the connection URL

fly secrets set \
  AUTHENTIK_SECRET_KEY="$(openssl rand -hex 50)" \
  AUTHENTIK_POSTGRESQL__HOST="<host>" \
  AUTHENTIK_POSTGRESQL__USER="<user>" \
  AUTHENTIK_POSTGRESQL__PASSWORD="<password>" \
  AUTHENTIK_REDIS__URL="<redis-url>" \
  AUTHENTIK_BOOTSTRAP_EMAIL="you@example.com" \
  AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -hex 24)" \
  -a iam-authentik

cd infra/authentik && fly deploy
```

`AUTHENTIK_POSTGRESQL__NAME` is already `authentik` in `fly.toml`, so it is not
repeated here.

`AUTHENTIK_BOOTSTRAP_*` creates the `akadmin` account on first boot instead of making
you click through a setup wizard. Save that password — it is used on that first boot
only, and there is no second chance to read it.

### The token authentik pushes accounts with

authentik provisions *into* us over SCIM, and our SCIM server wants a bearer token.
Issue one from the console — **Provisioning in → Issue token** — and hand it over:

```bash
fly secrets set IAM_SCIM_TOKEN="<the token the console showed once>" -a iam-authentik
```

Only the hash is kept on our side, so the console cannot show it again. If it goes
missing, issue another and revoke the first.

Its database is a **second** Supabase project (or a second database in the same
one). Do not point it at ours: it would run its own migrations against our schema.

Once it is up, register it with the console the same way as locally — paste its
metadata, never fetch it
([ADR 0006](adr/0006-paste-metadata-do-not-fetch-it.md)):

```bash
curl -sSL https://iam-authentik.fly.dev/application/saml/iam-console/metadata/ -o idp.xml
# then POST it to /api/identity-providers, as in the README
```

The reply-URL inside authentik has to be the real hostname —
`https://iam-console.fly.dev/saml/acs` — not `localhost:8080`. A mismatch here is
the single most common deploy failure, and it surfaces as a refused assertion with
`Destination` in the reason, which the **Sign-ins** screen shows in full.

---

## 5. The hosted provider

A hosted tenant alongside authentik, which is what proves multi-provider federation
rather than one-provider federation. Nothing to run.

Whichever you use, the two values it needs from us:

| What              | Value                                       |
| ----------------- | ------------------------------------------- |
| ACS / reply URL   | `https://iam-console.fly.dev/saml/acs`      |
| Entity ID         | `https://iam-console.fly.dev/saml/metadata` |

Then paste its metadata into `/api/identity-providers` the same way.

---

## Afterwards

**Nobody is an admin yet.** A person created by logging in starts as an employee with
no console permissions — deliberately, so there is no path from "the provider let
them in" to "they can change things here". The first admin has to be granted by hand:

```bash
fly ssh console -a iam-console -C "python -m scripts.seed --help"
```

or a single UPDATE in the Supabase SQL editor, followed by using the console
properly. Note that `users.platform_role` is a *cache* of the person's role grants
and `iam/access/roles.py` is the only thing meant to write it, so a raw UPDATE is a
bootstrap step and not a habit.

**Supabase will keep warning that RLS is disabled.** That warning is aimed at people
exposing their database to browsers. We are not, because the Data API is off. Do not
"fix" it by enabling RLS without reading ADR 0002 first.

**The audit chain can be verified from the console** at `/api/audit/verify`. Worth
doing once after the first real login, because a chain that was going to break would
rather break in front of you than in front of somebody else.

---

## What is not done

- **No background worker.** Provisioning syncs run inside the request that asks for
  them. A first sync against a large directory is a slow HTTP call. A queue nothing
  drains would be worse than saying so.
- **No automated deploy.** `fly deploy` is run by hand. CI builds and tests the
  image; it does not release it.
- **Migrations are manual.** By design, see step 2.
