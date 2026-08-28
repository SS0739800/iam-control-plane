# IAM Control Plane

An identity control plane that speaks **both halves of SAML 2.0 and both halves
of SCIM 2.0**, with an HRMS as the downstream application that proves it works.

The HRMS is not the project. It is the thing being provisioned into and signed
into, which is what makes the identity platform demonstrable.

|                | Inbound — we receive                                     | Outbound — we send                                    |
| -------------- | -------------------------------------------------------- | ----------------------------------------------------- |
| **SAML 2.0**   | Service Provider: validate assertions from the IdP `P2`   | Identity Provider: sign and issue assertions `P5`     |
| **SCIM 2.0**   | SCIM server: accept user and group writes `P3`            | SCIM client: push accounts downstream `P6`            |

Upstream identity providers, in the order they get wired up: **authentik**
(self-hosted, local, no trial clock) → **Okta** (free plan, cloud) → **Entra ID**
(P2 trial, last).

---

## Status

**It is deployed and the whole loop runs on it.**
[iam-console.fly.dev](https://iam-console.fly.dev) authenticates against a real Okta
tenant, and [iam-hrms.fly.dev](https://iam-hrms.fly.dev) is the downstream it
provisions into. Somebody signs in through Okta, an admin grants them access to the
HRMS, a sync pushes them there, marking them a leaver switches the account off — and
the record stays, because a system that keeps payroll history has reasons to keep it.

A push to `sudaiv-work` deploys both, but only after the tests, the types, the
linters and the xmlsec source build all pass. `/api/health` reports the commit it is
running, so "Fly said it worked" and "this commit is serving traffic" are different
questions with the same answer.

What is *not* done is worth reading too: the
[deploy runbook's last section](docs/deploy.md#what-is-not-done) lists it, and
authentik is not deployed, so multi-provider federation is unproven in production.

### Phase 2 — inbound SSO

A real login against a real authentik goes
the whole way and comes back: out through `/saml/login`, a password typed at the
provider, in through `/saml/acs`, a genuine signature checked with xmlsec, all ten
checks passed, a person created, a session issued, and a cookie the API
authenticates every later request with. Signing out ends the session here *and*
at the provider, so clicking login again asks for a password instead of walking
straight back in. [Set it up below](#signing-in-for-real).

The **Sign-ins** screen is the part worth looking at. Every attempt shows all ten
checks with the values they compared, and a refused login keeps the document that
arrived. That is the payoff for writing the checks ourselves instead of calling
one library function — see
[ADR 0005](docs/adr/0005-validate-assertions-ourselves.md).

`python -m scripts.smoke_login` drives the whole loop with no browser and is the
only thing that can check it, because there is no identity provider in CI.

| Endpoint            | What                                                    |
| ------------------- | ------------------------------------------------------- |
| `/saml/metadata`    | Our details, for registering with a provider            |
| `/saml/login`       | Start a login                                           |
| `/saml/acs`         | Where the provider posts the answer                     |
| `/saml/logout`      | End the session here and at the provider                |
| `/saml/sls`         | Single logout, in both directions                        |
| `/api/me`           | Who the session says you are                            |
| `/api/saml/logins`  | The inspector's data                                    |

**The logout requests we send are signed**, and the certificate to verify them is
published in `/saml/metadata`. That pairing is one feature rather than two: Okta
refuses an unsigned `LogoutRequest`, and refuses a signed one it cannot check just as
firmly.

It is not XML signing, which is the whole difficulty. The redirect binding signs the
*query string* — `SAMLRequest=…&RelayState=…&SigAlg=…`, in that order, URL-encoded,
with `Signature=` appended. Sign the decoded XML, reorder the parameters, or
re-encode before signing and the result verifies against nothing, with a provider
error that says only "invalid signature". A happy side effect: it needs no `xmlsec`,
so those tests run on any machine rather than only in the container.

Until this existed, signing out ended our session and left the provider's intact, so
clicking sign in again walked straight back in without a password. authentik tolerated
unsigned messages and hid it; Okta did not.

The `X-Dev-Actor` header still answers for requests that arrive with no session
cookie, outside production only. That is impersonation, not authentication. A real
session always wins over it, and unsetting `DEV_ACTOR_USER_NAME` switches it off.
See [`iam/security/actor.py`](apps/api/iam/security/actor.py).

One thing to know before the demo: nobody becomes an admin by logging in. A
SAML-created person starts as an employee with no console permissions, on purpose,
so there is no path from "the provider let them in" to "they can change things
here". Granting a role is a deliberate admin action on the user's page, and it is
recorded as a grant with a reason, an author and an optional end date.

### Being the identity provider (P5)

The direction where applications take our word. `/idp/*` is the outbound half:
applications register against our metadata, send people here to be signed in, and
get back an assertion we signed.

| Endpoint             | What                                                     |
| -------------------- | -------------------------------------------------------- |
| `/idp/metadata`      | The document you hand somebody registering an application |
| `/idp/sso`           | Where an application sends people to be signed in         |
| `/idp/sso/{slug}`    | A login we start ourselves, for a link in the console     |

Three things have to be true before anything is signed, and each is a different
refusal: the application is registered and switched on, somebody is signed in, and
that person has an assignment giving them access. The third is where P4 stops being
a report and becomes enforcement — an assertion is only ever issued to somebody a
row says may have it, and the refusal is written to the audit log with the reason.

**The address in the request is never used.** An AuthnRequest names where to send
the answer, and honouring it is the worst mistake available on this endpoint:
anybody can send a request naming a real application and their own return address,
and posting there would hand them a genuine signed assertion for whoever happened to
be logged in. The registered `acs_url` is the only one an assertion goes to. The
request's copy is read, logged when it disagrees, and dropped.

Refusals after the first step come back as SAML rather than as an error page, so
somebody halfway through signing in lands back at the application with something it
can explain instead of stranded on our domain. The one exception is a request we
cannot read or from an application we do not know — there is no trusted address to
post anything to, so those are plain HTTP errors.

The signing key is the most dangerous secret here. It never goes in the database,
production refuses to start without one, and outside production a throwaway pair is
generated in memory with a warning. See [`iam/saml/keys.py`](apps/api/iam/saml/keys.py).

### Deploying it (P7)

Three Fly apps and a Neon database. The full runbook is
[docs/deploy.md](docs/deploy.md); the shape is:

| App             | Process  | What                                     |
| --------------- | -------- | ---------------------------------------- |
| `iam-console`   | `app`    | The API and the frontend, one process    |
| `iam-console`   | `worker` | Sweeps provisioning targets on a timer   |
| `iam-hrms`      |          | The downstream we provision into         |
| `iam-authentik` |          | Self-hosted provider — not deployed yet  |

Two processes from one image. They fail differently and should be scaled
differently: a sweep that wedges must not take the console down, and a console under
load must not delay somebody's offboarding. The worker is the smaller of the two
because it never loads `xmlsec` — nothing on `iam.worker`'s import path touches the
SAML machinery.

**The console is one app serving both halves.** In production FastAPI serves the
built bundle itself, so the origin is single because there is only one server
rather than because a proxy was configured to look that way. Caddy stays for local
development, where it is doing real work in front of the Vite dev server. See
[ADR 0008](docs/adr/0008-one-server-serves-both-halves-in-production.md).

That decision has one honest cost, and it is written down rather than discovered:
`/users` is a React route with no file behind it, and locally the Vite dev server
invents `index.html` for paths it does not recognise — so deep links work in
development whether or not anybody made them work in production. The first
implementation used `StaticFiles(html=True)` and broke exactly there: that flag
serves `index.html` for a *directory*, and on a real miss looks for `404.html`.
`iam/frontend.py` does it properly, and the tests check both that a deep link
resolves and that `/api/nonsense` is still a 404 rather than a web page.

**Vercel was considered and does not work** for the API half. `xmlsec` has to be
compiled against the system `libxml2`, which needs a Dockerfile
([ADR 0004](docs/adr/0004-build-xmlsec-from-source.md)); a serverless Python runtime
cannot do it at all. The frontend would have been fine there, but once a Docker host
exists for the API, authentik and the HRMS, serving 417 KB of static files from it is
free.

**The database is Neon, not Supabase** — see
[ADR 0009](docs/adr/0009-neon-hosts-postgres.md), which amends ADR 0002. Supabase's
free tier cannot fit this project: it manages one database per project and allows
two projects, and this needs two databases — ours and authentik's, because authentik
runs its own migrations and would rewrite our schema. Local has always run two
databases on one server, and Neon does the same. ADR 0002 anticipated the move and
said it would be a connection-string change; it was.

One trap worth knowing about, because it has an unhelpful failure mode. Neon hands
out URLs ending `?sslmode=require&channel_binding=require` — both libpq spellings,
neither of which asyncpg accepts, and SQLAlchemy forwards query parameters to the
driver untranslated. So a pasted URL raises `TypeError: connect() got an unexpected
keyword argument 'sslmode'` on the first query, and the readiness endpoint hides
exception messages (they can contain the connection string), so production would
report only `{"detail": "TypeError"}`. `iam/config.py` renames `sslmode` and drops
`channel_binding`, which asyncpg cannot honour at all;
`tests/test_connection_urls.py` checks both against SQLAlchemy's own dialect rather
than against a string.

**Nobody is an admin on a fresh deployment**, which is the correct default and also a
chicken-and-egg problem: there is no root account, so there is nobody who can grant
the first admin. `scripts/grant_first_admin.py` closes that one gap and refuses to run
a second time, because a bootstrap that keeps working is a backdoor. It grants through
the same code path the console uses, so the grant and the cached role agree and
`find_drift` stays quiet.

One limitation stated rather than hidden: migrations are run by hand.

Provisioning no longer waits for anybody. A second process sweeps every enabled
target every five minutes, so a leaver's downstream account switches off on its own —
which is how it now works in production, watched end to end from an Okta
unassignment. **Sync now** is still there for impatience and for forcing a retry,
which the timer deliberately never does.

A push to `sudaiv-work` deploys both apps, but only after the whole pipeline passes —
Fly has no git integration of its own, so `.github/workflows/ci.yml` is what makes a
push a release. The job then asks the running machine whether its `git_sha` matches
the commit, which is what turns "Fly said it worked" into "this commit is serving
traffic". See [docs/deploy.md](docs/deploy.md#deploying-by-pushing).

### Provisioning outward, and the HRMS (P6)

The half that writes to other systems. **Provisioning out** in the console
registers a downstream, checks it answers, and pushes accounts to it. Who gets
pushed is whoever has access to the application behind it — there is no second
list to keep in step.

The downstream that proves it is `apps/hrms`: a small HRMS in its own container,
with its own storage and its own bearer token, that **shares no code with the
platform**. That separation is the whole value of it. Two halves of a protocol
that import the same constants agree by construction rather than by conformance,
and the interesting bugs live exactly where two independent readings of a
specification differ. Its staff directory is at **http://localhost:8090** and
everybody on it was put there by us.

| What                       | Where                                            |
| -------------------------- | ------------------------------------------------ |
| The console screen         | **Provisioning out**                             |
| The downstream itself       | http://localhost:8090                            |
| Its SCIM root, from the api | `http://hrms:8000/scim/v2`                      |
| The whole loop, end to end  | `python -m scripts.smoke_provisioning`           |

Four things worth knowing:

**A leaver is switched off, not deleted.** We send `PATCH active: false`, never
`DELETE`. The system at the other end usually has reasons to keep the record —
payroll history, an audit trail, a rehire — and a rehire gets their old account
back rather than a second one.

**An account that already exists is adopted, not fought.** A 409 on create means
somebody already works there, so we go and find their account and link to it.
Without that, onboarding any system with staff already in it fails forever.

**The token we send is encrypted, not hashed.** Inbound tokens are hashed, so
there is nothing to give back. This one has to be sent, so it is encrypted at
rest — and precisely because we *could* return it, no endpoint and no screen ever
does. Rotating means sending a new one. See
[`iam/secrets.py`](apps/api/iam/secrets.py).

**Orphans are the number that matters.** An orphan is somebody we tried to remove
from a downstream and could not, so they still have access there and nobody would
know. Everything else on that screen can be read from a log; that one means
somebody has to go and do something, which is why it is the only figure coloured
red.

A background sweep runs every five minutes, so nothing waits for somebody to press
a button. A sweep rather than a queue, and that is the design rather than the
shortcut: `reconcile()` asks who should have an account here and what this system
actually has, then fixes the difference — so a timer converges no matter what
happened in between. A dropped queue message would mean somebody keeps access
forever with nothing noticing; a missed sweep is fixed by the next one.

It never forces. Forcing retries links past their attempt limit, and doing that
every five minutes turns one broken target into permanent load. **Sync now** can
force; a timer should not.

A manual first run against the seeded directory still pushes about 1,200 accounts
and takes roughly forty seconds — the sweep is incremental after that, because
nothing unchanged is pushed twice.

### Lifecycle and entitlements (P4)

Who has what, why, and what happens when that changes.

| Screen              | What it answers                                          |
| ------------------- | -------------------------------------------------------- |
| A user's page       | What can this person do here, since when, and who decided |
| **Access rules**    | What access follows automatically from who somebody is   |
| **Requests**        | Who has asked for what, and who answered                 |
| **Review**          | What is worth asking about right now                     |

Four decisions worth knowing:

**A console role is a grant, not a column.** `users.platform_role` is a cache of
the person's role grants, and `iam/access/roles.py` is the only thing that writes
it. That is what makes "why is this person an admin" answerable, and what lets
admin access expire on its own. One live grant per person, enforced by a partial
unique index.

**Granting a role has its own permission.** `roles:write`, admin only, and
deliberately not `users:write` — helpdesk holds that, so reusing it would let
anybody who can fix a misspelled name make themselves an admin.

**The last admin cannot be removed.** There is no root account, so an empty admin
set can only be fixed by editing the database by hand.

**Nobody approves their own request.** Checked in the service layer and held as a
CHECK constraint. Withdrawing your own is fine — the rule is about who may
*decide*.

Rules grant group membership from attributes, and reconcile rather than add: the
mover case is the one that goes unnoticed. `group_members.source` records whether
a membership came from the provider, a person, a rule or an approved request, and
the rule engine only ever removes its own — otherwise it would fight the SCIM sync
forever.

Approval email goes to Mailpit at http://localhost:8025.

CI runs on every push and deploys from `sudaiv-work` when it passes. Its first
green run found two things that were invisible locally: a test reading CI's own
environment variables, and SAML fixtures that had never been committed — so the
recorded assertion had sat in the repository since P2 with no certificate to verify
it against.

| Phase | Scope                                             | State           |
| ----- | ------------------------------------------------- | --------------- |
| P0    | Foundation: compose, CI, health probes            | ✅ done         |
| P1    | Core domain + admin console, hash-chained audit   | ✅ done         |
| P2    | SAML SP — inbound SSO                             | ✅ done         |
| P3    | SCIM 2.0 server — inbound provisioning            | ✅ done         |
| P4    | Lifecycle + entitlements *(MVP line)*             | ✅ done         |
| P5    | SAML IdP — outbound SSO                           | ✅ done         |
| P6    | SCIM client — outbound provisioning               | ✅ done         |
| P7    | Production deploy                                 | ✅ done         |
| P8    | Entra ID integration sprint                       | Okta done, Entra to go |

Okta is done, and it was the larger half. Inbound SCIM from a hosted provider was
the biggest untested surface in the project — the SCIM server had only ever been
written to by our own client and by authentik — and it now handles users, groups,
memberships, attribute updates and deactivation from Okta, including a group created
with both its members in one push.

Worth naming what that produced, because it was not all smooth. Okta briefly
deactivated the only admin, which revoked their role grant, which locked the console
until a script could be run over SSH. The last-admin guard cannot see that: it
refuses the change through `PATCH /api/users/{id}`, and the deactivation arrived over
SCIM. That is arguably correct — the provider is the directory of record — but it
means a single-admin deployment is one Okta hiccup from needing a shell.

What remains of the phase is **Entra**, whose claim URIs and SCIM behaviour differ
enough to be its own integration.

---

## Quickstart

**Prerequisite: Docker Desktop with the WSL 2 backend.** Not optional — the SAML
stack compiles `xmlsec` against `libxml2`, which has no usable Windows wheels.
See [ADR 0004](docs/adr/0004-build-xmlsec-from-source.md).

```bash
cp .env.example .env          # already done if .env exists
docker compose up             # first build takes several minutes
```

Then open **http://localhost:8080**. You should see the platform status page
reporting API liveness and database readiness — both served from the same origin,
which is the whole point of P0.

| URL                                  | What                                  |
| ------------------------------------ | ------------------------------------- |
| http://localhost:8080                | SPA                                   |
| http://localhost:8080/api/health     | Liveness probe                        |
| http://localhost:8080/api/docs       | OpenAPI browser                       |
| http://localhost:8025                | Mailpit — catches all outbound email  |
| http://localhost:8090                | The demo HRMS we provision into       |
| http://localhost:9000                | authentik (only with `--profile idp`) |

---

## Signing in for real

The identity provider is behind a compose profile so a plain `up` stays fast.
Start it when you want to actually sign in:

```bash
docker compose --profile idp up -d      # first pull is about a gigabyte
```

authentik configures itself. It creates its admin account from
`AUTHENTIK_BOOTSTRAP_PASSWORD`, and
[`infra/authentik/blueprints/iam-console.yaml`](infra/authentik/blueprints/iam-console.yaml)
declares the SAML application — the ACS address, the audience, the four attributes
it sends, and that the assertion itself gets signed. No clicking through a setup
wizard, and no demo that only works on the machine where somebody did the
clicking. Give it a minute; the first boot runs migrations.

Then register it here. Two steps, because **we never fetch a metadata URL** — see
[ADR 0006](docs/adr/0006-paste-metadata-do-not-fetch-it.md) for why that stays
true:

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

That prints the login link. Open it, sign in as `akadmin` with the bootstrap
password, and you land back on this side with a session.

To check the whole loop without a browser:

```bash
cd apps/api && python -m scripts.smoke_login
```

That is the only thing that can check it. There is no identity provider in CI, so
no test there sees a real assertion — and that gap is not theoretical. The xpath
bug in [`iam/saml/reader.py`](apps/api/iam/saml/reader.py) passed every unit test
and failed the first time a genuine authentik assertion arrived.

| URL                                    | What                                |
| -------------------------------------- | ----------------------------------- |
| http://localhost:8080/saml/login?idp=authentik | Start a login               |
| http://localhost:8080/saml/metadata    | Our metadata, for the provider      |
| http://localhost:8080/api/me           | Who the session says you are        |
| http://localhost:9000                  | authentik                           |

---

## Working on the API

Python dependencies live in a virtualenv at `apps/api/.venv`. **Every Python
command goes through it** — there is no global install and no `pip install`
outside it.

### First-time setup

Only if `apps/api/.venv` does not already exist. **Run it from inside `apps/api`** —
a venv records absolute paths at creation and cannot be moved afterwards, so one
created elsewhere and copied in will have a broken `activate` script and a
`VIRTUAL_ENV` pointing at nowhere.

```bash
cd apps/api
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install -r requirements-dev.txt
```

On macOS or Linux the interpreter is at `.venv/bin/python` instead.

If the venv is ever broken, delete and recreate rather than repairing it:

```bash
cd apps/api && rm -rf .venv && py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
```

Activating is optional. These both work:

```bash
source .venv/Scripts/activate   # prompt gains a (.venv) prefix; then: pytest
./.venv/Scripts/python.exe -m pytest    # no activation needed
```

Bare `python` in Git Bash without activating resolves to the global interpreter,
not this venv — a `ModuleNotFoundError` there means the shell, not a bad install.

Do **not** install `requirements-saml.txt` locally on Windows — it needs native
xmlsec headers and belongs to the Docker image.

### Commands

All run from `apps/api`:

| Task              | Command                                                      |
| ----------------- | ------------------------------------------------------------ |
| Lint              | `.venv/Scripts/python -m ruff check .`                       |
| Format            | `.venv/Scripts/python -m ruff format .`                      |
| Type check        | `.venv/Scripts/python -m mypy iam tests`                     |
| Test              | `.venv/Scripts/python -m pytest`                             |
| Test incl. DB     | `IAM_TEST_DATABASE_URL=... .venv/Scripts/python -m pytest`    |
| New migration     | `.venv/Scripts/python -m alembic revision --autogenerate -m "add users"` |
| Apply migrations  | `.venv/Scripts/python -m alembic upgrade head`                |
| Roll back one     | `.venv/Scripts/python -m alembic downgrade -1`                |

Tests that need Postgres are marked `integration` and skip when
`IAM_TEST_DATABASE_URL` is unset, so the suite runs on a laptop with nothing else
started. CI sets it from a service container.

Format generated migrations explicitly — there is no Alembic post-write hook, on
purpose:

```bash
.venv/Scripts/python -m ruff format alembic/versions
```

### Requirements files

| File                    | Contents                          | Installs on      |
| ----------------------- | --------------------------------- | ---------------- |
| `requirements.txt`      | Runtime                           | any platform     |
| `requirements-dev.txt`  | Runtime + pytest, ruff, mypy      | any platform     |
| `requirements-saml.txt` | lxml, xmlsec, python3-saml        | **Linux only**   |

Versions are pinned exactly. `pyproject.toml` carries tool configuration only —
no dependencies — so there is one source of truth for what gets installed.

---

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

Run the SPA through Caddy at `:8080`, not directly at Vite's `:5173`. Relative
API paths only resolve behind the proxy, and that constraint is deliberate — see
[ADR 0003](docs/adr/0003-single-origin.md).

### File watching on Windows

The repo sits on the Windows filesystem and is bind-mounted into Linux
containers. **inotify events do not cross that boundary for chokidar**, so Vite
runs with `server.watch.usePolling` enabled in `vite.config.ts`. Without it,
edits are silently ignored and the page simply never updates — verified by
editing `vite.config.ts` and getting no restart until polling was turned on.

`uvicorn --reload` needs no equivalent flag: its `watchfiles` backend does pick up
Windows-side edits on this setup. If that ever regresses, the fallback is
`WATCHFILES_FORCE_POLLING=true` in the api service environment.

Both workarounds become unnecessary if the repo moves into the WSL 2 filesystem
(`~/projects/...` inside Ubuntu, opened through VS Code's WSL extension), where
native events work and file I/O is faster.

---

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
      routers/          HTTP surfaces; /api/* plus the browser-facing /saml/*
      saml/             the SAML machinery — see the note below
      security/         permissions, and working out who's calling
    alembic/            migrations
    scripts/            seed data, schema export, the first-admin bootstrap,
                        the end-to-end login and provisioning checks
    tests/
      fixtures/         a real authentik assertion and the cert that signed it
    requirements*.txt
    Dockerfile          two-stage; builds xmlsec from source
  web/                  Vite + React 19 + TypeScript SPA
    src/
      lib/api.ts        typed client, generated from openapi.json
  hrms/                 the downstream we provision into — shares no code with
                        the platform, on purpose
docs/adr/               architecture decision records
docs/deploy.md          the production runbook
Dockerfile              the production console: API + built frontend, one image
fly.toml                the console app
infra/db/init/          first-boot Postgres bootstrap
infra/authentik/        the SAML application, declared as a blueprint
Caddyfile               single-origin route table
docker-compose.yml
```

Inside `iam/saml/`, one file is different from the others:

```
sp.py            our side: who we are, and the request that starts a login
reader.py        reads the XML and verifies the signature   <- needs xmlsec
checks.py        the ten rules a login has to pass once it's been read
metadata.py      reads a provider's metadata, to register them
provisioning.py  turning a passed login into a person
sessions.py      keeping them signed in afterwards
```

`reader.py` is the only one that needs `xmlsec`, so it is the only one that cannot
run on Windows. Everything else is comparisons and database work and is tested
anywhere, which is deliberate — see
[ADR 0005](docs/adr/0005-validate-assertions-ourselves.md). `reader.py` itself is
tested against a real assertion inside the container, in the `images` CI job.

---

## Decisions worth knowing before you change anything

Full records in [`docs/adr/`](docs/adr/). The short version:

- **[The database host is Postgres and nothing else](docs/adr/0002-supabase-is-postgres-only.md).**
  No hosted auth service, no RLS. This project *is* an identity system; adopting a
  second one would mean two sources of truth about who someone is. Written for
  Supabase, where it also meant disabling the Data API — with RLS off, PostgREST
  plus the public `anon` key exposes every table.
- **[Neon hosts Postgres](docs/adr/0009-neon-hosts-postgres.md)**, amending the
  above. Supabase's free tier cannot hold two databases and this needs two. The
  schema was kept portable from P0 precisely so this would be a connection-string
  change, and it was. It buys a quota, not a smaller attack surface: Neon has a Data
  API and an auth service of its own, so every rule in ADR 0002 still applies and
  the runbook still verifies the Data API is off.
- **[One origin](docs/adr/0003-single-origin.md).** Caddy serves the SPA and the
  API from one hostname, so the session cookie stays first-party and there is no
  CORS layer at all. SAML request state lives in Postgres keyed by `RelayState`,
  never in a cookie — `SameSite=Lax` cookies are not sent on the IdP's cross-site
  POST to our ACS endpoint.
- **[xmlsec is built from source](docs/adr/0004-build-xmlsec-from-source.md).**
  Mixing a prebuilt `lxml` wheel with a source-built `xmlsec` segfaults at
  runtime rather than failing at install. Do not remove `--no-binary`.
- **`/saml/acs` gets its reader through a dependency.** `iam/saml/reader.py` is
  the only module that needs xmlsec, so importing it at the top of the router
  would make the whole app unimportable on Windows and in the `api` CI job.
  Injecting it also means the tests can hand the endpoint prepared facts and
  cover every decision after the signature check — the ten checks, creating the
  person, the session, the cookie, the redirect — without xmlsec anywhere. The
  signature check itself stays real and is exercised by the image build.
- **Liveness and readiness are separate.** `/api/health` never touches Postgres,
  so a database blip cannot get a healthy container killed;
  `/api/health/ready` returns 503 so a load balancer drains instead.

---

## CI

Three jobs on every push and pull request:

- **api** — ruff, `ruff format --check`, mypy strict, `alembic upgrade head`
  against an empty database, pytest with a Postgres service container.
- **web** — `tsc --noEmit`, vitest, production build.
- **images** — builds the API image, which is what proves the xmlsec source build
  still works, then runs the signature-verification tests inside it. Those cannot
  run in the **api** job, because there is no xmlsec there. Slowest job, and the
  reason a segfault in the SAML stack will not be a surprise.

What CI cannot check is a login against a real identity provider: there isn't one
in CI. `python -m scripts.smoke_login` is that check, and it has to be run by hand.
# HRMS-IAM-CLOUD
# HRMS-CLOUD-IAM
# HRMS-CLOUD-IAM
# HRMS-CLOUD-IAM
