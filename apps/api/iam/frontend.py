"""Serving the built frontend from this process.

In production one server answers for both halves — see
docs/adr/0008-one-server-serves-both-halves-in-production.md.

Plain ``StaticFiles(html=True)`` isn't enough: it serves ``index.html`` for a
directory request like ``/``, but a path with no file behind it (like the React
route ``/users``) just 404s. So a miss on an unknown path falls through to
``index.html`` with a 200 and lets the browser router handle it — except for the
API's own prefixes and missing assets, which must still 404 (an API 404 that came
back as HTML would look like a broken client, and a missing JS bundle served as
HTML fails with a confusing error).
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

    Only for paths that could plausibly be a route in the browser. An API prefix
    or a missing asset still 404s.
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
            # Serve the app itself, for the browser's router to interpret.
            return await super().get_response(self._index, scope)

    def _is_browser_route(self, path: str) -> bool:
        """Whether a miss on this path should be answered with the application.

        Args:
            path: The request path, relative to the mount, as StaticFiles passes
                it in. On Windows this uses backslashes (``api\\nonsense``), so it
                must be normalized before comparing against "api/" or it silently
                matches nothing.
        """
        tidied = path.replace("\\", "/").lstrip("/")
        if tidied.startswith(API_PREFIXES):
            return False
        if tidied.startswith(ASSET_PREFIXES):
            return False
        # A path with a file extension is asking for a file, not a page. Serving
        # the app in place of a missing favicon.ico would make the browser parse
        # HTML as whatever it expected.
        return "." not in tidied.rsplit("/", 1)[-1]


def resolve_bundle(directory: str) -> pathlib.Path:
    """Check the bundle is really there, and hand back its path.

    Fails at startup instead of serving a blank site in front of a healthy API
    with a passing health check.

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
