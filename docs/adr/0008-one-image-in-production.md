# 8. In production, one server serves both halves

- **Status:** accepted
- **Date:** 2026-08-20

## Context

[ADR 0003](0003-single-origin.md) put the frontend and the API on one hostname so
the session cookie stays first-party and there is no CORS to configure. Locally
that is Caddy: it matches `/api`, `/saml`, `/scim` and `/idp` to the API and sends
everything else to the Vite dev server.

Production is being deployed to Fly.io, and two things about that change the
calculation.

**The frontend is not a runtime.** It is 417 KB of static files. The `build` target
in `apps/web/Dockerfile` has always said so — "P7 copies it into the Caddy image
rather than running Node in production at all". There is no Node process to host,
which is also why serverless platforms were never an option for the API half: the
API needs `xmlsec` compiled against the system `libxml2`, and that requires a
Dockerfile ([ADR 0004](0004-build-xmlsec-from-source.md)).

**Fly's edge already does most of Caddy's job.** TLS termination, certificates,
HTTP/2, and compression happen before a request reaches the machine. What is left
of the Caddyfile in production is a route table and an SPA fallback.

So the question is what still serves the static files. Three shapes were on the
table:

- **Two apps.** A public Caddy app holding `dist`, proxying to a private API app.
  Mirrors compose exactly.
- **One app, two processes.** Caddy and uvicorn in one image, under a supervisor.
- **One app, one process.** The API serves `dist` itself.

## Decision

The console runs as **one Fly app, one process**. FastAPI serves the built bundle
from `/`.

Not with `StaticFiles(html=True)`, which was the first attempt and does not work.
That flag handles a *directory* request — ask for `/` and get `index.html` — and
does nothing for a path with no file behind it. On a real miss Starlette looks for
`404.html` and, finding none, returns a 404. So every deep link would break, which
is precisely the trap the Caddyfile's own P7 note had already spotted for the
`file_server` case.

`iam/frontend.py` subclasses it instead: a 404 on something that looks like a
browser route falls through to `index.html` with a 200, and the router in the
browser resolves it. Paths that are *not* browser routes keep their 404 — anything
under an API prefix, anything under `assets/`, and anything with a file extension.
Answering those with a web page turns a clear failure into a confusing one: a
client asking for a route that does not exist gets HTML with a success code, and a
missing bundle file makes the browser parse HTML as JavaScript and blame the wrong
thing.

This satisfies ADR 0003 more strongly than the local setup does: the origin is
single because there is only one server, not because a proxy was configured to make
it look that way. There is no route table to drift.

It fits because nothing was mounted at `/` — every router carries a prefix, so a
static mount at the root conflicts with none of them.

Worth being precise about why, because the obvious version of this sentence is
wrong: an API path *does* reach the static handler. A mount at `/` matches
everything, so `/api/nonsense` gets there once the routers have declined it. What
keeps it a 404 is the guard, not the routing. Mounting last is necessary but not
sufficient, and the tests check both halves.

Supporting decisions:

- **The bundle is optional.** `STATIC_DIR` unset means no mount and no behaviour
  change, which is what local development and every test run does. A missing
  directory is a startup error rather than a silent 404-for-everything, because
  "the API works and the site is blank" is a bad afternoon.
- **The prefix guard normalises separators.** `StaticFiles` hands paths to the
  subclass with *operating system* separators, not URL ones, so on Windows
  `/api/nonsense` arrives with a backslash separator, so a check against `"api/"`
  matches nothing. That is a bug that works in the Linux container and quietly does
  not in a developer's test run, which is the worst shape a bug can have.
- **Caddy stays for local development, unchanged.** There it is doing real work:
  proxying the Vite dev server and passing its hot-reload websocket through. The
  production path not using Caddy does not make it useless locally.
- **The HRMS and authentik are their own Fly apps.** They are separate systems —
  that is the entire point of the HRMS ([P6](../../README.md)) — and collapsing
  them into this image would undo it.
- **`/api/health` stays the health check.** Fly checks the API, not the static
  files, because a machine serving the bundle with a dead database is not healthy.

## Consequences

- One image, one deploy, one thing to reason about. No supervisor, no second app,
  no internal hop on the SAML POST path.
- **Local and production differ in how the frontend is served.** Locally: Vite
  through Caddy. In production: `StaticFiles` through FastAPI. That is a real
  divergence and the honest cost of this decision. It is bounded — the divergence
  is "who returns index.html", and the routes, origin and cookie behaviour are
  identical either way — but a bug that only appears when the bundle is served
  statically will not show up locally. The deploy runbook therefore includes
  loading a deep link directly, which is the failure this would cause.
- Static files are served by a Python process rather than a Go one. At 417 KB
  behind Fly's edge cache this does not matter, and if it ever does, putting Caddy
  back is a Dockerfile change rather than a rewrite.
- Moving off Fly to somewhere without edge TLS means terminating TLS again. The
  Caddyfile is still in the repository and still correct for that.
