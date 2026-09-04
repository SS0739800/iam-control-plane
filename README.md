# IAM Control Plane

An identity platform that implements both directions of SAML 2.0 and both
directions of SCIM 2.0, with a small HRMS as the downstream system it signs people
into and provisions accounts for.

|              | Inbound (we receive)                        | Outbound (we send)                       |
| ------------ | ------------------------------------------- | ---------------------------------------- |
| **SAML 2.0** | Service provider: validate assertions       | Identity provider: sign and issue them   |
| **SCIM 2.0** | SCIM server: accept user and group writes   | SCIM client: push accounts downstream    |

Providers it talks to, in the order they were wired up: authentik (self-hosted),
Okta, and Entra ID.

## Status

Deployed, and the whole loop runs on it.
[iam-console.fly.dev](https://iam-console.fly.dev) authenticates against a real Okta
tenant and provisions into [iam-hrms.fly.dev](https://iam-hrms.fly.dev). Someone
signs in through Okta, an admin grants them access to the HRMS, a sync pushes them
there, and marking them a leaver switches the account off downstream.

Pushing to `sudaiv-work` deploys both apps once the tests, types, linters and the
xmlsec build pass. `/api/health` reports the commit it's running, so you can check
which one is actually serving traffic.

Okta is fully integrated, including inbound SCIM — users, groups, memberships,
attribute updates and deactivation. Entra ID is the remaining piece; its claim URIs
and SCIM behaviour differ enough to need its own work.

authentik isn't deployed, so multi-provider federation is only proven locally.
[The deploy runbook](docs/deploy.md#what-is-not-done) lists the other gaps.

It was built in phases, each one a working slice rather than a layer:

| Phase | Scope                                           | State                  |
| ----- | ----------------------------------------------- | ---------------------- |
| P0    | Foundation: compose, CI, health probes          | done                   |
| P1    | Core domain + admin console, hash-chained audit | done                   |
| P2    | SAML SP, inbound SSO                            | done                   |
| P3    | SCIM 2.0 server, inbound provisioning           | done                   |
| P4    | Lifecycle + entitlements *(MVP line)*           | done                   |
| P5    | SAML IdP, outbound SSO                          | done                   |
| P6    | SCIM client, outbound provisioning              | done                   |
| P7    | Production deploy                               | done                   |
| P8    | Entra ID integration                            | Okta done, Entra to go |

P8 turned up something worth recording: Okta briefly deactivated the only admin,
which revoked their role grant and locked the console until a script could be run
over SSH. The last-admin guard can't catch that — it refuses the change through
`PATCH /api/users/{id}`, and this arrived over SCIM. Arguably correct, since the
provider is the directory of record, but it means a single-admin deployment is one
provider hiccup away from needing a shell.

## Quickstart

You need Docker Desktop with the WSL 2 backend. The SAML stack compiles xmlsec
against libxml2 and there are no usable Windows wheels for it
([ADR 0004](docs/adr/0004-build-xmlsec-from-source.md)).

```bash
cp .env.example .env          # skip if .env already exists
docker compose up             # first build takes a few minutes
```

Then open http://localhost:8080.

| URL                              | What                                  |
| -------------------------------- | ------------------------------------- |
| http://localhost:8080            | The console                           |
| http://localhost:8080/api/health | Liveness probe                        |
| http://localhost:8080/api/docs   | OpenAPI browser                       |
| http://localhost:8025            | Mailpit, catches outbound email       |
| http://localhost:8090            | The HRMS we provision into            |
| http://localhost:9000            | authentik (needs `--profile idp`)     |

## Signing in for real

authentik sits behind a compose profile so a plain `up` stays quick:

```bash
docker compose --profile idp up -d      # first pull is about a gigabyte
```

It configures itself from
[`infra/authentik/blueprints/iam-console.yaml`](infra/authentik/blueprints/iam-console.yaml),
which declares the SAML application, the ACS address, the audience and the
attributes it sends. Give it a minute on first boot for migrations.

Then register it here. It's two steps because the server never fetches a metadata
URL — see [ADR 0006](docs/adr/0006-paste-metadata.md):

```bash
curl -sSL http://localhost:9000/application/saml/iam-console/metadata/ -o idp.xml

python - <<'PY'
import json, pathlib, urllib.request
body = json.dumps({
    "slug": "authentik",
    "name": "authentik (local)",
    "metadata_xml": pathlib.Path("idp.xml").read_text(encoding="utf-8"),
}).encode()
request = urllib.request.Request(
    "http://localhost:8080/api/identity-providers",
    data=body,
    headers={"Content-Type": "application/json"},
)
print(json.loads(urllib.request.urlopen(request).read())["login_url"])
PY
```

That prints a login link. Sign in as `akadmin` with the bootstrap password and you
land back here with a session.

To check the loop without a browser:

```bash
cd apps/api && python -m scripts.smoke_login
```

That script is the only thing that tests a real login, since there's no identity
provider in CI. It earns its keep: an xpath bug in
[`iam/saml/reader.py`](apps/api/iam/saml/reader.py) passed every unit test and only
showed up against a genuine authentik assertion.

## What it does

### Inbound SSO

A login goes out through `/saml/login`, the password is typed at the provider, and
the answer comes back to `/saml/acs`, where the signature is checked with xmlsec and
the assertion has to pass ten checks before anyone is signed in. Signing out ends the
session here and at the provider.

The **Sign-ins** screen shows every attempt with all ten checks and the values they
compared, and keeps the document that arrived for any login that was refused. That
detail is why the checks are written here instead of handed to a library
([ADR 0005](docs/adr/0005-validate-assertions-ourselves.md)).

| Endpoint           | What                                          |
| ------------------ | --------------------------------------------- |
| `/saml/metadata`   | Our details, for registering with a provider  |
| `/saml/login`      | Start a login                                 |
| `/saml/acs`        | Where the provider posts the answer           |
| `/saml/logout`     | End the session here and at the provider      |
| `/saml/sls`        | Single logout, both directions                |
| `/api/me`          | Who the session says you are                  |

Logout requests are signed, and the certificate to verify them is published in
`/saml/metadata`. Okta refuses an unsigned `LogoutRequest` and equally refuses a
signed one it can't verify, so the two go together.

The signing is fiddlier than it sounds. The redirect binding signs the *query
string* — `SAMLRequest=…&RelayState=…&SigAlg=…`, in that order, URL-encoded, with
`Signature=` appended. Sign the decoded XML, reorder the parameters or re-encode
before signing and it verifies against nothing, with the provider reporting only
"invalid signature". It needs no xmlsec, so those tests run anywhere.

Logging in doesn't make anyone an admin. A person created by SAML starts as an
employee with no console permissions; granting a role is a separate admin action
recorded with a reason, an author and an optional end date.

Outside production, an `X-Dev-Actor` header answers for requests with no session
cookie. That's impersonation, not authentication — a real session always wins, and
unsetting `DEV_ACTOR_USER_NAME` turns it off. See
[`iam/security/actor.py`](apps/api/iam/security/actor.py).

### Being the identity provider

`/idp/*` is the other direction: applications register against our metadata, send
people here to sign in, and get back an assertion we signed.

| Endpoint          | What                                                      |
| ----------------- | --------------------------------------------------------- |
| `/idp/metadata`   | The document you hand somebody registering an application |
| `/idp/sso`        | Where an application sends people to sign in              |
| `/idp/sso/{slug}` | A login we start ourselves, for a link in the console     |

Three things have to hold before anything gets signed, each with its own refusal:
the application is registered and enabled, someone is signed in, and that person has
an assignment granting them access. Refusals are written to the audit log with the
reason.

The address in the request is ignored. An AuthnRequest names where to send the
answer, and honouring it would let anyone send a request naming a real application
with their own return address and collect a signed assertion for whoever was logged
in. Only the registered `acs_url` is ever used; the request's copy is logged when it
disagrees and then dropped.

Refusals after the first step come back as SAML rather than an error page, so
someone halfway through a login lands back at the application with something it can
explain. The exceptions are a request we can't read or an application we don't know,
where there's no trusted address to reply to.

The signing key never goes in the database. Production won't start without one, and
outside production a throwaway pair is generated in memory with a warning. See
[`iam/saml/keys.py`](apps/api/iam/saml/keys.py).

### Provisioning outward, and the HRMS

**Provisioning out** registers a downstream system, checks it answers, and pushes
accounts to it. Who gets pushed is whoever has access to the application behind it,
so there's no second list to maintain.

The downstream is `apps/hrms`: a small HRMS in its own container with its own storage
and bearer token, sharing no code with the platform. That's the point of it — two
halves of a protocol that import the same constants agree automatically, and the
interesting bugs are where two independent readings of a spec differ.

| What                        | Where                                  |
| --------------------------- | -------------------------------------- |
| The console screen          | **Provisioning out**                   |
| The HRMS itself             | http://localhost:8090                  |
| Its SCIM root, from the api | `http://hrms:8000/scim/v2`             |
| The whole loop              | `python -m scripts.smoke_provisioning` |

A few details:

A leaver is switched off with `PATCH active: false`, never deleted. The system at the
other end usually has reasons to keep the record, and a rehire gets their old account
back instead of a second one.

An account that already exists is adopted. A 409 on create means the person already
works there, so we find their account and link to it. Without that, onboarding any
system with existing staff would fail every time.

The token we send is encrypted rather than hashed, because unlike an inbound token it
has to be sent. No endpoint or screen ever returns it, and rotating means sending a
new one. See [`iam/secrets.py`](apps/api/iam/secrets.py).

Orphans are the number that matters — someone we tried to remove from a downstream
and couldn't, who therefore still has access there. Everything else on that screen
can be read from a log; an orphan means somebody has to go and fix something, which
is why it's the only figure in red.

A worker sweeps every enabled target every five minutes. It reconciles rather than
queues: it asks who should have an account and what the system actually has, then
fixes the difference, so it converges regardless of what happened in between. It
never forces retries past the attempt limit — **Sync now** can do that, a timer
shouldn't. A first run against the seeded directory pushes about 1,200 accounts in
roughly forty seconds; after that it's incremental.

### Lifecycle and entitlements

| Screen           | What it answers                                           |
| ---------------- | --------------------------------------------------------- |
| A user's page    | What can this person do here, since when, and who decided |
| **Access rules** | What access follows automatically from who someone is     |
| **Requests**     | Who has asked for what, and who answered                  |
| **Review**       | What is worth asking about right now                      |

A console role is a grant, not a column. `users.platform_role` caches the person's
role grants and `iam/access/roles.py` is the only thing that writes it, which is what
makes "why is this person an admin" answerable and lets admin access expire on its
own. One live grant per person, enforced by a partial unique index.

Granting a role needs `roles:write`, admin only, separate from `users:write` — which
helpdesk holds, so sharing them would let anyone who can fix a misspelled name make
themselves an admin.

The last admin can't be removed. There's no root account, so an empty admin set can
only be fixed by hand against the database.

Nobody approves their own request. It's checked in the service layer and held as a
CHECK constraint. Withdrawing your own is fine; the rule is about deciding.

Rules grant group membership from attributes and reconcile rather than add, since the
mover case is the one that goes unnoticed. `group_members.source` records whether a
membership came from the provider, a person, a rule or an approved request, and the
rule engine only removes its own — otherwise it would fight the SCIM sync forever.

Approval email goes to Mailpit at http://localhost:8025.

### Deployment

Three Fly apps and a Neon database. Full runbook in [docs/deploy.md](docs/deploy.md).

| App             | Process  | What                                    |
| --------------- | -------- | --------------------------------------- |
| `iam-console`   | `app`    | The API and the frontend, one process   |
| `iam-console`   | `worker` | Sweeps provisioning targets on a timer  |
| `iam-hrms`      |          | The downstream we provision into        |
| `iam-authentik` |          | Self-hosted provider, not deployed yet  |

Two processes from one image. They fail differently and should scale differently: a
wedged sweep shouldn't take the console down, and a busy console shouldn't delay
someone's offboarding. The worker never loads xmlsec, so it's the smaller of the two.

In production FastAPI serves the built bundle itself, so there's one origin because
there's one server ([ADR 0008](docs/adr/0008-one-image-in-production.md)). Caddy stays
for local development, where it fronts the Vite dev server.

That has one cost: `/users` is a React route with no file behind it, and
the Vite dev server invents `index.html` for paths it doesn't recognise, so deep links
work locally whether or not they work in production. The first version used
`StaticFiles(html=True)` and broke exactly there — that flag serves `index.html` for a
*directory* and looks for `404.html` on a real miss. `iam/frontend.py` handles it, and
the tests check both that a deep link resolves and that `/api/nonsense` still 404s.

Vercel doesn't work for the API half: xmlsec has to be compiled against the system
libxml2, which needs a Dockerfile, and a serverless Python runtime can't do it. Once
a Docker host exists anyway, serving the static files from it is free.

The database is Neon ([ADR 0009](docs/adr/0009-neon-hosts-postgres.md), amending
[ADR 0002](docs/adr/0002-postgres-only.md)). Supabase's free tier manages one database
per project and allows two projects; this needs two databases, ours and authentik's,
because authentik runs its own migrations and would rewrite our schema.

One Neon trap with an unhelpful failure mode: its URLs end
`?sslmode=require&channel_binding=require`, both libpq spellings that asyncpg doesn't
accept, and SQLAlchemy forwards query parameters to the driver untranslated. A pasted
URL raises `TypeError: connect() got an unexpected keyword argument 'sslmode'` on the
first query, and since the readiness endpoint hides exception messages (they can
contain the connection string) production would report only `{"detail": "TypeError"}`.
`iam/config.py` renames `sslmode` and drops `channel_binding`;
`tests/test_connection_urls.py` checks both against SQLAlchemy's own dialect.

Nobody is an admin on a fresh deployment, which is the right default and also a
chicken-and-egg problem, since there's no root account to grant the first one.
`scripts/grant_first_admin.py` closes that gap and refuses to run twice. It grants
through the same code path the console uses, so the grant and the cached role agree.

Migrations are run by hand.

## Working on the API

Python dependencies live in a virtualenv at `apps/api/.venv`. Every Python command
goes through it; there's no global install.

### First-time setup

Only if `apps/api/.venv` doesn't exist. Run it from inside `apps/api` — a venv records
absolute paths when it's created and can't be moved afterwards.

```bash
cd apps/api
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install -r requirements-dev.txt
```

On macOS or Linux the interpreter is at `.venv/bin/python`.

If the venv breaks, delete and recreate it rather than repairing it:

```bash
cd apps/api && rm -rf .venv && py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
```

Activating is optional — both of these work:

```bash
source .venv/Scripts/activate   # then: pytest
./.venv/Scripts/python.exe -m pytest
```

Bare `python` in Git Bash without activating resolves to the global interpreter, so a
`ModuleNotFoundError` there is the shell, not a bad install.

Don't install `requirements-saml.txt` locally on Windows; it needs native xmlsec
headers and belongs to the Docker image.

### Commands

All from `apps/api`:

| Task             | Command                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| Lint             | `.venv/Scripts/python -m ruff check .`                                  |
| Format           | `.venv/Scripts/python -m ruff format .`                                 |
| Type check       | `.venv/Scripts/python -m mypy iam tests`                                |
| Test             | `.venv/Scripts/python -m pytest`                                        |
| Test incl. DB    | `IAM_TEST_DATABASE_URL=... .venv/Scripts/python -m pytest`              |
| New migration    | `.venv/Scripts/python -m alembic revision --autogenerate -m "add users"` |
| Apply migrations | `.venv/Scripts/python -m alembic upgrade head`                          |
| Roll back one    | `.venv/Scripts/python -m alembic downgrade -1`                          |

Tests needing Postgres are marked `integration` and skip when
`IAM_TEST_DATABASE_URL` is unset, so the suite runs on a laptop with nothing else
started. CI sets it from a service container.

There's no Alembic post-write hook, so format generated migrations yourself:

```bash
.venv/Scripts/python -m ruff format alembic/versions
```

### Requirements files

| File                    | Contents                     | Installs on   |
| ----------------------- | ---------------------------- | ------------- |
| `requirements.txt`      | Runtime                      | any platform  |
| `requirements-dev.txt`  | Runtime + pytest, ruff, mypy | any platform  |
| `requirements-saml.txt` | lxml, xmlsec, python3-saml   | Linux only    |

Versions are pinned exactly. `pyproject.toml` carries tool configuration only, so
there's one source of truth for what gets installed.

## Working on the web app

```bash
cd apps/web
npm ci
```

| Task       | Command             |
| ---------- | ------------------- |
| Dev server | `npm run dev`       |
| Type check | `npm run typecheck` |
| Test       | `npm run test`      |
| Build      | `npm run build`     |

Run the SPA through Caddy at `:8080`, not Vite's `:5173` directly — relative API paths
only resolve behind the proxy ([ADR 0003](docs/adr/0003-single-origin.md)).

### File watching on Windows

The repo sits on the Windows filesystem and is bind-mounted into Linux containers, and
inotify events don't cross that boundary for chokidar. Vite runs with
`server.watch.usePolling` in `vite.config.ts` because of it. Without that, edits are
silently ignored and the page never updates.

`uvicorn --reload` doesn't need the equivalent; its watchfiles backend picks up
Windows-side edits fine here. If that regresses, set
`WATCHFILES_FORCE_POLLING=true` on the api service.

Both workarounds go away if the repo moves into the WSL 2 filesystem, where native
events work and file I/O is faster.

## Layout

```
apps/
  api/                  FastAPI service
    iam/
      config.py         environment-backed settings
      db.py             engine construction, session dependency, pooler modes
      deps.py           shared FastAPI dependencies
      logging_setup.py  structured JSON logging
      main.py           application factory
      models/           SQLAlchemy declarative models
      routers/          HTTP surfaces: /api/* plus the browser-facing /saml/*
      saml/             the SAML machinery, see below
      security/         permissions, and working out who's calling
    alembic/            migrations
    scripts/            seed data, schema export, first-admin bootstrap,
                        end-to-end login and provisioning checks
    tests/
      fixtures/         a real authentik assertion and the cert that signed it
    Dockerfile          two-stage, builds xmlsec from source
  web/                  Vite + React 19 + TypeScript SPA
    src/
      lib/api.ts        typed client, generated from openapi.json
  hrms/                 the downstream we provision into, shares no code
docs/adr/               architecture decision records
docs/deploy.md          production runbook
Dockerfile              production console: API + built frontend, one image
fly.toml                the console app
infra/db/init/          first-boot Postgres bootstrap
infra/authentik/        the SAML application, as a blueprint
Caddyfile               single-origin route table
docker-compose.yml
```

Inside `iam/saml/`:

```
sp.py            our side: who we are, and the request that starts a login
reader.py        reads the XML and verifies the signature   <- needs xmlsec
checks.py        the ten rules a login has to pass once it's read
metadata.py      reads a provider's metadata, to register them
provisioning.py  turning a passed login into a person
sessions.py      keeping them signed in afterwards
```

`reader.py` is the only one needing xmlsec, so it's the only one that can't run on
Windows. Everything else is comparisons and database work, and is tested anywhere
([ADR 0005](docs/adr/0005-validate-assertions-ourselves.md)). `reader.py` is tested
against a real assertion inside the container, in the `images` CI job.

## Decisions

Full records in [`docs/adr/`](docs/adr/). The short version:

- **[Postgres and nothing else](docs/adr/0002-postgres-only.md).** No hosted auth
  service, no RLS. This project is an identity system; adopting a second one would
  mean two sources of truth about who someone is.
- **[Neon hosts Postgres](docs/adr/0009-neon-hosts-postgres.md)**, amending the above.
  Supabase's free tier can't hold two databases and this needs two. The schema was
  kept portable so this would be a connection-string change, and it was.
- **[One origin](docs/adr/0003-single-origin.md).** The SPA and API share a hostname,
  so the session cookie stays first-party and there's no CORS layer. SAML request
  state lives in Postgres keyed by `RelayState`, never in a cookie, since `SameSite=Lax`
  cookies aren't sent on the IdP's cross-site POST to our ACS endpoint.
- **[xmlsec is built from source](docs/adr/0004-build-xmlsec-from-source.md).** Mixing
  a prebuilt lxml wheel with a source-built xmlsec segfaults at runtime rather than
  failing at install. Don't remove `--no-binary`.
- **`/saml/acs` gets its reader through a dependency.** `iam/saml/reader.py` is the
  only module needing xmlsec, so importing it at the top of the router would make the
  app unimportable on Windows and in the `api` CI job. Injecting it also lets the
  tests hand the endpoint prepared facts and cover everything after the signature
  check without xmlsec. The signature check itself is exercised by the image build.
- **Liveness and readiness are separate.** `/api/health` never touches Postgres, so a
  database blip can't get a healthy container killed. `/api/health/ready` returns 503
  so a load balancer drains instead.

## CI

Three jobs on every push and pull request:

- **api** — ruff, `ruff format --check`, mypy strict, `alembic upgrade head` against
  an empty database, pytest with a Postgres service container.
- **web** — `tsc --noEmit`, vitest, production build.
- **images** — builds the API image, which is what proves the xmlsec source build
  still works, then runs the signature-verification tests inside it. Those can't run
  in the api job because there's no xmlsec there. Slowest job.

CI can't check a login against a real identity provider, since there isn't one.
`python -m scripts.smoke_login` covers that, by hand.
