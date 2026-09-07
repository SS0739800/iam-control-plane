"""Response headers that harden the browser side of the console.

The API enforces access on its own; these are the belt-and-suspenders layer that
lives in the browser. None of them change what a request is allowed to do — they
change what a page loaded from us is allowed to do once it's rendered.

What each one is for:

- **X-Frame-Options / frame-ancestors** — nobody gets to put this console in an
  iframe. It's an admin tool for identity; framing it is only ever a clickjacking
  setup, and there's no legitimate reason to embed it.
- **X-Content-Type-Options: nosniff** — the browser trusts the Content-Type we
  send instead of guessing, so a file can't be coaxed into running as script.
- **Referrer-Policy** — a full URL isn't leaked to another site; only the origin
  crosses over, which matters when we hand off to an identity provider.
- **Strict-Transport-Security** — once seen, the browser refuses to talk to us
  over plain HTTP. Production only, since it's meaningless (and awkward to undo)
  against a local http:// dev server.
- **Content-Security-Policy** — everything the page loads comes from us. The app
  is one same-origin script and one same-origin stylesheet, so this is tight
  without any special-casing.

Two deliberate holes in the CSP:

- `form-action` is left off. Signing in can mean auto-posting a SAML request to
  whichever provider a tenant registered, and we can't know those origins ahead
  of time — pinning form-action would break login for exactly the providers this
  is meant to support.
- `/api/docs` is exempt. Swagger UI pulls its assets from a CDN and runs an
  inline bootstrap script, so a self-only policy would blank the page. The docs
  are a convenience surface, not somewhere untrusted input renders.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.requests import Request

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self'",
        "connect-src 'self'",
    )
)

# Two years. Long enough to be worth having; the browser only ever learns it over
# a connection that already succeeded on HTTPS.
STRICT_TRANSPORT_SECURITY = "max-age=63072000; includeSubDomains"


def install_security_headers(app: FastAPI, *, is_production: bool) -> None:
    """Attach the header middleware to the app.

    ``is_production`` gates only HSTS — the rest are safe everywhere and run in
    local development too, so a missing header shows up before it reaches prod.
    """

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)

        # setdefault so a handler that has a reason to set its own value wins;
        # nothing does today, but this keeps the middleware from silently
        # overriding one that might later.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        if is_production:
            response.headers.setdefault("Strict-Transport-Security", STRICT_TRANSPORT_SECURITY)

        # Swagger UI at /api/docs loads from a CDN and can't live under a
        # self-only policy — see the module docstring.
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)

        return response
