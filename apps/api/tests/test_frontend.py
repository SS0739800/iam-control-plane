"""Serving the built frontend from the API process.

In production one server answers for both halves — see
docs/adr/0008-one-image-in-production.md. Two failure
modes here are easy to miss, and both look like a working API next to a
broken website.

First, mounting order: every router carries a prefix so a static mount at "/"
doesn't conflict with them today, but if the mount ever goes first, every API
route starts returning index.html with a 200 instead.

Second, deep links: /users and /groups are React routes with no file behind
them. Locally the Vite dev server invents index.html for unknown paths; a
plain file server 404s them instead, so only the home page would load.
"""

from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from iam.main import create_app
from tests.support import build_settings

INDEX = "<!doctype html><title>IAM Control Plane</title><div id=root></div>"


@pytest.fixture
def bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    """A directory shaped like a real `npm run build` output."""
    (tmp_path / "index.html").write_text(INDEX, encoding="utf-8")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index-abc123.js").write_text("console.log('hello')", encoding="utf-8")
    (assets / "index-abc123.css").write_text("body{color:red}", encoding="utf-8")
    return tmp_path


def client_serving(bundle: pathlib.Path) -> TestClient:
    settings = build_settings().model_copy(update={"static_dir": str(bundle)})
    return TestClient(create_app(settings))


# ------------------------------------------------------- serving the bundle


def test_the_home_page_comes_from_the_bundle(bundle: pathlib.Path) -> None:
    response = client_serving(bundle).get("/")

    assert response.status_code == 200
    assert "IAM Control Plane" in response.text


def test_the_hashed_assets_are_served(bundle: pathlib.Path) -> None:
    response = client_serving(bundle).get("/assets/index-abc123.js")

    assert response.status_code == 200
    assert "hello" in response.text


def test_a_deep_link_gets_index_html_rather_than_a_404(bundle: pathlib.Path) -> None:
    """The failure that would only appear in production.

    /users is a React route. Locally Vite invents index.html for unrecognized
    paths; a plain file server would 404 instead.
    """
    response = client_serving(bundle).get("/users")

    assert response.status_code == 200
    assert "IAM Control Plane" in response.text


def test_a_deep_link_several_levels_down_works_too(bundle: pathlib.Path) -> None:
    response = client_serving(bundle).get("/applications/some-uuid-here")

    assert response.status_code == 200
    assert "IAM Control Plane" in response.text


# ------------------------------------------- and does not eat the API with it


def test_the_api_still_answers_json(bundle: pathlib.Path) -> None:
    """The mounting-order test.

    If the static mount is ever registered before the routers, this returns
    index.html with a 200 and every client breaks silently.
    """
    response = client_serving(bundle).get("/api/health")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "IAM Control Plane" not in response.text


def test_the_openapi_schema_is_not_the_frontend(bundle: pathlib.Path) -> None:
    response = client_serving(bundle).get("/api/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "IAM Control Plane"


def test_the_saml_and_scim_paths_are_not_the_frontend(bundle: pathlib.Path) -> None:
    """These sit outside /api because providers post to them directly, which
    makes them the likeliest to be shadowed by a root mount.

    Used as a context manager since the SCIM token check needs a session
    factory, built by the lifespan, which TestClient only runs once entered.
    The database is never reached — the refusal happens before any query.
    """
    with client_serving(bundle) as client:
        metadata = client.get("/saml/metadata")
        assert "IAM Control Plane" not in metadata.text

        scim = client.get("/scim/v2/ServiceProviderConfig")
        # Unauthenticated, so this is a refusal — but a SCIM refusal, not a web page.
        assert scim.status_code in (401, 403)
        assert "IAM Control Plane" not in scim.text


# ------------------------------------------------------------- the switch off


def test_no_static_dir_means_no_mount() -> None:
    """What local development and every other test does.

    The API must be complete on its own — requiring a built frontend to start
    would make the test suite depend on npm.
    """
    client = TestClient(create_app(build_settings()))

    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 404


def test_a_static_dir_with_nothing_in_it_refuses_to_start(tmp_path: pathlib.Path) -> None:
    """Loud rather than lazy.

    A wrong path would otherwise be a blank site in front of a healthy API
    with a passing health check.
    """
    settings = build_settings().model_copy(update={"static_dir": str(tmp_path)})

    with pytest.raises(RuntimeError, match="no index.html"):
        create_app(settings)


def test_a_static_dir_that_does_not_exist_refuses_to_start(tmp_path: pathlib.Path) -> None:
    settings = build_settings().model_copy(update={"static_dir": str(tmp_path / "nope")})

    with pytest.raises(RuntimeError, match="no index.html"):
        create_app(settings)


def test_a_missing_asset_stays_a_404(bundle: pathlib.Path) -> None:
    """Not the application.

    If a missing bundle file returned index.html, the browser would try to
    run HTML as JavaScript, and the error would point at the bundle rather
    than the deploy that lost it.
    """
    response = client_serving(bundle).get("/assets/index-deadbeef.js")

    assert response.status_code == 404


def test_a_missing_file_at_the_root_stays_a_404(bundle: pathlib.Path) -> None:
    """Anything with an extension is asking for a file, not a page."""
    response = client_serving(bundle).get("/robots.txt")

    assert response.status_code == 404


def test_an_unknown_api_path_stays_a_404(bundle: pathlib.Path) -> None:
    """The one that matters most: a broken client asking for a route that
    doesn't exist has to be told so, not handed HTML with a 200."""
    response = client_serving(bundle).get("/api/nonsense")

    assert response.status_code == 404
    assert "IAM Control Plane" not in response.text
