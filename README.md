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

**Phase 2 — inbound SSO. Working end to end.** A real login against a real
authentik goes the whole way and comes back: out through `/saml/login`, a password
typed at the provider, in through `/saml/acs`, a genuine signature checked with
xmlsec, all ten checks passed, a person created, a session issued, and a cookie
the API authenticates every later request with. `POST /saml/logout` ends it.
`GET /api/me` says who you are. [Set it up below](#signing-in-for-real).

`python -m scripts.smoke_login` drives that whole loop with no browser and is the
only thing that can check it, because there is no identity provider in CI.

Still to come in P2: the login inspector screen, and Single Logout at
`/saml/sls` — which the metadata already advertises, and which needs a signing key
that arrives in P5.

The `X-Dev-Actor` header still answers for requests that arrive with no session
cookie, outside production only. That is impersonation, not authentication. A real
session always wins over it, and unsetting `DEV_ACTOR_USER_NAME` switches it off.
See [`iam/security/actor.py`](apps/api/iam/security/actor.py).

CI is configured but has not run yet — it executes on the first push to a remote.

| Phase | Scope                                             | State           |
| ----- | ------------------------------------------------- | --------------- |
| P0    | Foundation: compose, CI, health probes            | ✅ done         |
| P1    | Core domain + admin console, hash-chained audit   | ✅ done         |
| P2    | SAML SP — inbound SSO                             | 🚧 in progress  |
| P3    | SCIM 2.0 server — inbound provisioning            | planned         |
| P4    | Lifecycle + entitlements *(MVP line)*             | planned         |
| P5    | SAML IdP — outbound SSO                           | planned         |
| P6    | SCIM client — outbound provisioning               | planned         |
| P7    | Production deploy                                 | planned         |
| P8    | Entra ID integration sprint                       | planned         |

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
    scripts/            seed data, schema export, the end-to-end login check
    tests/
      fixtures/         a real authentik assertion and the cert that signed it
    requirements*.txt
    Dockerfile          two-stage; builds xmlsec from source
  web/                  Vite + React 19 + TypeScript SPA
    src/
      lib/api.ts        typed client, generated from openapi.json
docs/adr/               architecture decision records
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

- **[Supabase is Postgres only](docs/adr/0002-supabase-is-postgres-only.md).** No
  Supabase Auth, no RLS, and the Data API is disabled. This project *is* an
  identity system; adopting a second one would mean two sources of truth about
  who someone is. Disabling the Data API is also a real security fix — with RLS
  off, PostgREST plus the public `anon` key exposes every table.
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
