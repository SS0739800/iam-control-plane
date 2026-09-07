"""The browser-hardening headers.

These ride on every response, so a missing one is easy to not notice until a
scanner or a review points it out. The checks here are the standing reminder of
which headers we promise and, for the two with a condition on them, when.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam.http_headers import install_security_headers


def test_the_hardening_headers_are_on_a_normal_response(client: TestClient) -> None:
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_the_content_security_policy_forbids_framing(client: TestClient) -> None:
    csp = client.get("/api/health").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'self'" in csp


def test_the_docs_are_exempt_from_the_policy(client: TestClient) -> None:
    """Swagger UI loads from a CDN and would blank out under a self-only policy.

    The other headers still apply there; only the CSP is lifted.
    """
    response = client.get("/api/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"


def test_hsts_is_absent_outside_production(client: TestClient) -> None:
    # The test app runs as ci, not production, so it must not tell a browser to
    # pin HTTPS — that would be miserable to undo against a local http server.
    assert "Strict-Transport-Security" not in client.get("/api/health").headers


def _mini_app(*, is_production: bool) -> TestClient:
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    install_security_headers(app, is_production=is_production)
    return TestClient(app)


def test_hsts_appears_only_when_production() -> None:
    with_hsts = _mini_app(is_production=True).get("/ping").headers
    without = _mini_app(is_production=False).get("/ping").headers
    assert with_hsts["Strict-Transport-Security"].startswith("max-age=")
    assert "Strict-Transport-Security" not in without
