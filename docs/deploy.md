# Deploying

Three Fly apps and a Neon database.

| App            | What                                             | Public |
| -------------- | ------------------------------------------------ | ------ |
| `iam-console`  | The API and the frontend, one process            | yes    |
| `iam-hrms`     | The downstream we provision into                 | yes    |
| `iam-authentik`| The identity provider, server and worker         | yes    |

The console is one app serving both halves — see
[ADR 0008](adr/0008-one-image-in-production.md). The HRMS is its
own app because it is meant to be a genuinely separate system. authentik is its own
app because it is somebody else's software.

The database is Neon — see [ADR 0009](adr/0009-neon-hosts-postgres.md), which
amends [ADR 0002](adr/0002-postgres-only.md). Supabase's free tier
cannot fit this project: it manages one database per project, allows two projects,
and this needs two databases.

---

## 0. Before anything

**The command is `flyctl`, not `fly`.** The Windows installer places only
`flyctl.exe` — there is no `fly.exe` alias, unlike on macOS and Linux where the
installer creates both. Every command below uses `flyctl` for that reason.

Also: `.flyin` goes on the user PATH at install time, so an already-open terminal
will not find it. Open a new one.

```bash
# flyctl, if it isn't there yet
curl -L https://fly.io/install.sh | sh
flyctl auth login
```

You need: a Fly account with a card on file (the free allowance still asks for one),
and a Neon project.

---

## 1. Neon

**Do this first, before running any migration.**

1. Create the project. Note the region — put the Fly apps in the same one, because
   every request the console serves does at least one query and a cross-continent
   round trip shows up immediately.

2. Create **two databases** in it. Ours, and authentik's:

   ```sql
   -- in Neon's SQL editor
   CREATE DATABASE iam;
   CREATE DATABASE authentik;
   ```

   Two, not one, because authentik runs its own migrations and would rewrite our
   schema if pointed at ours. This is the same arrangement local uses — see
   `infra/db/init/01-create-databases.sh`, which has done it this way since P0.

   Skip the `authentik` one if you are deferring section 4.

3. Collect **two connection strings** for the `iam` database, from the dashboard's
   connection panel. They are different and both are needed:

   | Which                            | Host             | Used for        |
   | -------------------------------- | ---------------- | --------------- |
   | Pooled (PgBouncer, transaction)  | `...-pooler...`  | the running app |
   | Direct                           | no `-pooler`     | migrations only |

   Migrations cannot run through transaction-mode pooling — schema changes and a
   transaction pooler do not mix. That is why `ALEMBIC_DATABASE_URL` exists
   separately from `DATABASE_URL`.

   Change the scheme to `postgresql+asyncpg://` and otherwise paste them as given:

   ```
   postgresql+asyncpg://<user>:<pw>@ep-xxx-pooler.<region>.aws.neon.tech/iam?sslmode=require
   postgresql+asyncpg://<user>:<pw>@ep-xxx.<region>.aws.neon.tech/iam?sslmode=require
   ```

   **Leave `?sslmode=require` alone.** asyncpg does not accept that spelling —
   `connect()` takes `ssl` — and `iam/config.py` rewrites the key for you. Without
   that rewrite the first query raises `TypeError: connect() got an unexpected
   keyword argument 'sslmode'`, and because the readiness endpoint hides exception
   messages (they can contain the connection string) production would only tell you
   `{"detail": "TypeError"}`. See [ADR 0009](adr/0009-neon-hosts-postgres.md).

4. **Check the Data API is off — before the first table exists.**

   Neon's connection dialog has **Data API**, **Auth** and **Storage** tabs. Do not
   assume they are inert. A REST endpoint over `users` and `audit_events`, reachable
   with a public key, is the worst finding this project could have, and it does not
   care which vendor is hosting.

   Open the **Data API** tab. If it is enabled, disable it. Then verify with a
   request rather than trusting the toggle — if the tab shows a base URL:

   ```bash
   curl -s -o /dev/null -w '%{http_code}
' "<data-api-url>/users"
   # want: anything that is not 200 with a body
   ```

   Leave **Auth** alone too. Sessions here are server-side rows keyed to a HttpOnly
   cookie; this project *is* the identity system. See
   [ADR 0002](adr/0002-postgres-only.md), which applies to Neon exactly
   as it did to Supabase.

---

## 2. The console

```bash
flyctl apps create iam-console
```

### The hostname

`BASE_URL` is set in `fly.toml`, not as a secret, and it is the setting most likely
to be forgotten because nothing breaks loudly when it is.

It defaults to `http://localhost:8080`. A deployment that leaves it there serves
metadata advertising localhost as its entity ID and reply URL — which an identity
provider accepts without complaint and then cannot reach. The failure surfaces much
later, as a login that goes out and never comes back.

It also decides the links in approval emails and the login URLs the console shows.

If the hostname changes, every identity provider registered against it has to be
re-registered. Decide it once.

### Secrets

Generate them rather than inventing them.

The `$(openssl rand -hex 32)` below is bash. In PowerShell it does nothing useful —
`openssl` may not be installed, and `$(...)` will not substitute the way you expect.
Either run these from Git Bash, or generate the value first in PowerShell and paste
it:

```powershell
# A cryptographically random 32-byte hex string. Not Get-Random, which is not
# suitable for a secret that signs session cookies.
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
```

Multi-line secrets — the SAML key below — are worse in PowerShell, because a
here-string needs its closing `'@` at column zero and the value must survive
unaltered. Use Git Bash for those, or `flyctl secrets import` and paste.

```bash
# The session secret. Production refuses to start if this is still the placeholder.
flyctl secrets set SESSION_SECRET="$(openssl rand -hex 32)" -a iam-console

# Both database URLs from step 1.
flyctl secrets set \
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
flyctl secrets set SAML_IDP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----" -a iam-console

flyctl secrets set SAML_IDP_CERTIFICATE="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----" -a iam-console
```

Production **will not start** without these. Outside production
a throwaway pair is generated in memory, and a key that changes on every restart
would silently invalidate every assertion we ever signed.

Keep a copy somewhere you would keep a private key. Fly will not show it to you
again.

### Deploy

```bash
flyctl deploy                    # from the repository root; reads ./fly.toml
```

The build compiles `xmlsec` from source and takes several minutes the first time
([ADR 0004](adr/0004-build-xmlsec-from-source.md)). It is also the step most likely
to fail, and it fails loudly — the image asserts `xmlsec.init()` works in both the
builder and the runtime stage, and that the frontend bundle arrived.

### Migrate

The image does not migrate on boot. Two machines starting at once would
run Alembic twice, and a migration is not something to race.

```bash
flyctl ssh console -a iam-console -C "python -m alembic upgrade head"
```

### Check it

```bash
flyctl open -a iam-console
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
flyctl apps create iam-hrms
flyctl volumes create hrms_data --size 1 -a iam-hrms
flyctl secrets set HRMS_SCIM_TOKEN="$(openssl rand -hex 32)" -a iam-hrms
flyctl deploy
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
[ADR 0007](adr/0007-outbound-allowlist.md) refuses
in production unless `ALLOW_PRIVATE_PROVISIONING_TARGETS` is set. It is set in
`fly.toml`, and the target records the concession so it reads as a
decision rather than an oversight.

Then **Check it answers**, then **Sync now**. That first sync runs inside the
request and pushes everybody entitled to the application — around forty seconds
against a seeded directory of 1,200.

After that it looks after itself. The `worker` process sweeps every enabled target
every five minutes, so a leaver's account closes without anybody pressing anything.
**Sync now** stays useful for impatience and for forcing a retry of links that have
failed their attempt limit, which the sweep never does on its own.

---

## 4. authentik

The heaviest part of this deploy, and the part to cut first if the bill matters. It
needs a server, a worker, Redis, and its own database — separate from ours, because
it owns its schema.

```bash
flyctl apps create iam-authentik
flyctl volumes create authentik_media --size 1 -a iam-authentik

# Redis. Upstash via Fly, or any Redis you already have.
flyctl redis create                      # note the connection URL

flyctl secrets set \
  AUTHENTIK_SECRET_KEY="$(openssl rand -hex 50)" \
  AUTHENTIK_POSTGRESQL__HOST="<host>" \
  AUTHENTIK_POSTGRESQL__USER="<user>" \
  AUTHENTIK_POSTGRESQL__PASSWORD="<password>" \
  AUTHENTIK_REDIS__URL="<redis-url>" \
  AUTHENTIK_BOOTSTRAP_EMAIL="you@example.com" \
  AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -hex 24)" \
  -a iam-authentik

cd infra/authentik && flyctl deploy
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
flyctl secrets set IAM_SCIM_TOKEN="<the token the console showed once>" -a iam-authentik
```

Only the hash is kept on our side, so the console cannot show it again. If it goes
missing, issue another and revoke the first.

Its database is the **second database in the Neon project**, created in step 1.
Do not point it at ours: it would run its own migrations against our schema. This is
the same arrangement local uses — see `infra/db/init/01-create-databases.sh`.

Once it is up, register it with the console the same way as locally — paste its
metadata, never fetch it
([ADR 0006](adr/0006-paste-metadata.md)):

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

## Deploying by pushing

A push to `sudaiv-work` runs the full pipeline and, if every job passes, releases
both apps. Fly has no git integration of its own — unlike Render, it will not watch a
branch — so `.github/workflows/ci.yml` is the piece that turns a push into a release.

The order matters more than the automation: the deploy job `needs: [api, web, images]`,
so a release cannot happen unless the tests, the types, the linters and the
xmlsec/lxml source build all agreed first. That is the part a `flyctl deploy` from a
laptop does not give you.

### One-time setup

```bash
# A token with access to both apps, so app-scoped will not do.
flyctl tokens create org --name github-actions
```

Then add it as a repository secret named exactly `FLY_API_TOKEN` — Settings →
Secrets and variables → Actions. Without it the deploy job fails at the first
`flyctl` call; the test jobs are unaffected.

### Which branch

`sudaiv-work`, for now, because that is where every phase lands and `main` is merged
only at the end — so deploying from `main` would mean one release months from now.

**This is temporary and should move to `main` once the project settles.** A branch
that deploys ought to be a branch that is reviewed, and this one is neither. The
tests in front of it are what make that survivable rather than reckless. The switch
is one line in `ci.yml`, marked with a comment saying so.

### What it checks after deploying

A deploy Fly calls successful can still be serving a broken app, so the job asks the
running machine four things:

| Check | Catches |
| ------------------------------- | --------------------------------------------- |
| `git_sha` matches the commit    | a failed rollout leaving the old release up   |
| `/api/health/ready`             | started, but cannot reach Postgres            |
| `<div id="root">` is served     | the bundle missing from the image             |
| `/users` returns 200            | the SPA fallback broken in production         |
| the HRMS answers                | one app released and the other not            |

The `git_sha` check is the one that makes this more than a smoke test: it proves the
machine now answering is running *this* commit. Until this existed every release
reported `"git_sha":"dev"`, and the only way to tell what was running was to guess
from timestamps.

---

## Afterwards

**Nobody is an admin yet.** A person created by logging in starts as an employee with
no console permissions, so there is no path from "the provider let
them in" to "they can change things here". Which leaves a gap on day one: nobody
exists who can grant anything, including the first admin.

**Log in through the identity provider once first.** The person has to exist before
they can be granted anything, and they are created by that first login. Then:

```bash
flyctl ssh console -a iam-console -C "python -m scripts.grant_first_admin you@example.com"
```

That goes through the same `grant_role` the console uses, so the grant and the cached
`users.platform_role` agree and `find_drift` stays quiet. It records an audit entry
with `actor_type: system` and `bootstrap: true`, because this is the one admin grant
on the whole log that no person is accountable for and it should be obvious which one
it is.

**It refuses to run twice.** Once any live admin grant exists, it stops and names who
holds it. A bootstrap that keeps working is a backdoor, and every admin after the
first is a decision somebody should make in the console. If it refuses unexpectedly,
somebody already has admin on that database and the interesting question is who.

Do **not** use `scripts/seed.py` for this. It populates a development directory with
1,284 fictional people, and its `--reset` flag empties every table first.

Do **not** set `users.platform_role` by hand either. It is a *cache* of the person's
role grants, and `iam/access/roles.py` is the only thing meant to write it — a raw
UPDATE produces somebody the console calls an admin with no grant behind them, which
is exactly what `find_drift` exists to report.

**RLS stays off.** Authorization lives in the application layer,
where the entitlement model is. On Neon nothing nags about this and there is no
public REST surface over the tables to worry about — which is most of why ADR 0002's
warnings are now moot rather than merely obeyed. Read ADR 0002 before changing it.

**The audit chain can be verified from the console** at `/api/audit/verify`. Worth
doing once after the first real login, because a chain that was going to break would
rather break in front of you than in front of somebody else.

---

## What it costs

Fly is not free. It bills by usage, and does not *collect* bills under $5 on a
personal organisation — which works like a free tier until it doesn't.

Three machines running continuously came to roughly $7 a month, so the first full
month would have been charged. Two of the three are idle almost all the time, so
they now sleep:

| Machine                    | Size  | Runs                      |
| -------------------------- | ----- | ------------------------- |
| `iam-console` — `app`      | 256MB | wakes on a request        |
| `iam-console` — `worker`   | 256MB | always, it is a timer     |
| `iam-hrms`                 | 256MB | wakes on a request        |
| `hrms_data` volume         | 1 GB  | always                    |

That lands around $2.50 of usage, which is not collected. The worker is most of it
and cannot sleep: it has no HTTP surface to wake it.

**Two things to understand rather than assume.**

The threshold is a cliff. A month at $5.20 is charged $5.20, not $0.20. The gap
between the estimate and the threshold is your safety margin, so set a spend
limit on the organisation rather than trusting arithmetic — including this
arithmetic.

Waking costs a second or two on the first request. An earlier version of this file
pinned a machine up to avoid that, reasoning that a link taking fifty seconds to
answer is a link nobody waits for. That is true of platforms whose cold start really
is that slow; Fly resumes a small machine fast enough that nobody notices.

**If $0 rather than "probably not collected" is the requirement**, the worker is the
thing to remove: drive the sweep from a scheduled GitHub Actions workflow calling an
authenticated endpoint, which is free for public repositories and fits because
reconcile is idempotent. The cost is a new authenticated surface and a cron that is
best-effort rather than punctual.

---

## What is not done

- **A sweep, not a queue.** The worker reconciles every five minutes rather than
  reacting to events. Worth knowing rather than a limitation: the worst case for an
  offboarding reaching a downstream is one interval, set by
  `PROVISIONING_SWEEP_SECONDS`.
- **Migrations are manual.** By design, see step 2.
