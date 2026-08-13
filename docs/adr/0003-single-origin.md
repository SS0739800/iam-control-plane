# 3. Serve the SPA and the API from one origin

- **Status:** accepted
- **Date:** 2026-08-10

## Context

The frontend is a static React SPA and the backend is FastAPI. The default
arrangement — SPA on a CDN host, API on its own hostname — breaks authentication
here in two separate ways.

**The session cookie becomes third-party.** With the SPA on one registrable
domain and the API on another, the API's cookie is third-party from the SPA's
point of view. That requires `SameSite=None; Secure` and depends on third-party
cookies, which browsers now block by default. The failure mode is the worst kind:
login works in one browser and not another, intermittently.

**Cross-site POST drops `SameSite=Lax` cookies.** The SAML POST binding is the
IdP rendering an auto-submitting form that POSTs the assertion to our ACS
endpoint. `Lax` cookies are not sent on cross-site POSTs — only on top-level GET
navigation. Any state we keep in a cookie between issuing an `AuthnRequest` and
receiving the assertion is silently absent on arrival.

## Decision

One hostname serves everything, with Caddy routing by path:

```
/                → SPA          (Vite dev server locally, static bundle in P7)
/api/*           → FastAPI      admin API, /api/docs, /api/openapi.json
/saml/*          → FastAPI      inbound SSO, we are the SP
/scim/v2/*       → FastAPI      inbound provisioning, we are the SCIM server
/idp/*           → FastAPI      outbound SSO, we are the IdP
```

Consequences of that choice, made explicit:

- The session cookie is first-party: `HttpOnly; Secure; SameSite=Lax`.
- **No CORS middleware.** Not "permissive CORS" — none. A cross-origin request is
  a misconfiguration and should fail loudly.
- FastAPI serves its docs and schema under `/api` so one proxy rule covers the
  whole API surface.
- The frontend uses relative paths only. There is no API base URL to configure,
  which means no environment-specific frontend build.
- SAML request state (the `AuthnRequest` ID, for `InResponseTo` validation) is
  stored in Postgres keyed by `RelayState`, **not** in a cookie. This sidesteps
  the `SameSite` problem entirely and gives replay protection for free.

## Consequences

- Caddy is a required component locally, not just in production. The Vite dev
  server needs `server.hmr.clientPort = 8080` so the HMR websocket connects back
  through the proxy rather than to Vite directly.
- The SPA loses CDN edge distribution. Irrelevant for an admin console behind a
  login.
- Deploying the frontend to Vercel later stays possible via a rewrite that
  proxies `/api/*` to the backend, preserving single origin.
- Caddy's route table and `iam/routers/__init__.py` must stay in agreement.
