"""Serving the built frontend from this process.

In production one server answers for both halves — see
docs/adr/0008-one-server-serves-both-halves-in-production.md.

Why this is not just StaticFiles(html=True)
-------------------------------------------

Because that does not do what its name suggests, and the difference is the whole
reason this file exists.

``html=True`` handles a *directory* request: ask for ``/`` and you get
``index.html``. It does nothing for a path that does not exist on disk. On a real
miss it looks for ``404.html`` and, finding none, returns a 404.

Which is correct behaviour for a website and wrong for a single-page application.
``/users`` and ``/applications/<id>`` are React routes with no file behind them.
The router in the browser resolves them, but the browser has to be given the
application first, and it asks the server for ``/users`` to get it.

Locally this never comes up: the Vite dev server invents ``index.html`` for
anything it does not recognise, so deep links work without anybody deciding they
should. The Caddyfile's own P7 note spotted the same trap for the static-file
case — "a plain file_server would 404 on every deep link and only the home page
would load".

So a miss falls through to ``index.html`` with a 200, and the browser sorts it out.

What still has to 404
---------------------

Everything under the API's own prefixes. A request for ``/api/nonsense`` must be a
404, not the web application, or a broken client gets HTML with a success code and
no way to tell that anything went wrong. That is handled by mounting this last, so
the routers claim their prefixes first — and because relying on mounting order is
fragile, the prefixes are also refused here explicitly.

A missing asset must 404 too. If ``/assets/index-abc123.js`` returned
``index.html``, the browser would try to run HTML as JavaScript, and the console
error points at the bundle rather than at the deploy that lost it.
"""

from __future__ import annotations

import pathlib

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

# Prefixes that belong to the API and must never be answered with the frontend.
# Kept in step with the routers in iam/main.py by the tests in
# tests/test_serving_the_frontend.py.
API_PREFIXES = ("api/", "saml/", "scim/", "idp/")

# Where the compiled assets live inside the bundle. A miss under here is a missing
# file, not a route, so it stays a 404.
ASSET_PREFIXES = ("assets/",)


class SinglePageApp(StaticFiles):
    """Static files, with unknown paths falling through to index.html.

    Only for paths that could plausibly be a route in the browser. An API prefix or
    a missing asset still 404s, because answering those with a web page turns a
    clear failure into a confusing one.
    """

    def __init__(self, *, directory: pathlib.Path) -> None:
        super().__init__(directory=directory, html=True)
        self._index = "index.html"

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except HTTPException as refused:
            if refused.status_code != 404 or not self._is_browser_route(path):
                raise
            # The application itself, for the browser's router to interpret.
            return await super().get_response(self._index, scope)

    def _is_browser_route(self, path: str) -> bool:
        """Whether a miss on this path should be answered with the application.

        Args:
            path: The request path, relative to the mount, as StaticFiles passes it
                in — which means separators for the *operating system*, not the URL.
                On Windows ``/api/nonsense`` arrives as ``api\nonsense``, so
                comparing against "api/" silently matches nothing. That failure only
                shows up on one platform, which is the worst kind: it would work in
                the Linux container and quietly not in a developer's test run.
        """
        tidied = path.replace("\\", "/").lstrip("/")
        if tidied.startswith(API_PREFIXES):
            return False
        if tidied.startswith(ASSET_PREFIXES):
            return False
        # A path with a file extension is asking for a file, not a page. Serving
        # the application in place of a missing favicon.ico or robots.txt means the
        # browser parses HTML as whatever it expected, and the resulting error
        # names the wrong thing.
        return "." not in tidied.rsplit("/", 1)[-1]


def resolve_bundle(directory: str) -> pathlib.Path:
    """Check the bundle is really there, and hand back its path.

    Loud rather than lazy. A wrong path would otherwise be a blank site in front of
    a perfectly healthy API, with the health check still reporting success — so this
    refuses to let the process start instead of serving nothing convincingly.

    Args:
        directory: The configured STATIC_DIR.

    Returns:
        The directory, as a path.

    Raises:
        RuntimeError: If there is no index.html in it.
    """
    bundle = pathlib.Path(directory)
    if not (bundle / "index.html").is_file():
        raise RuntimeError(
            f"STATIC_DIR is {directory!r} but there is no index.html in it. "
            "Either point it at the built frontend or unset it."
        )
    return bundle
