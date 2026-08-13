"""Health probe behaviour.

These tests exist to pin the liveness/readiness split. It is an easy thing to
"simplify" later into one endpoint that checks the database, at which point a
transient Postgres blip starts killing containers.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from iam import __version__


def test_liveness_is_ok_without_a_database(client: TestClient) -> None:
    """Liveness must not depend on Postgres."""
    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["env"] == "ci"
    assert body["version"] == __version__


def test_liveness_reports_the_build_it_is_running(client: TestClient) -> None:
    """git_sha is how you tell what is actually deployed."""
    body = client.get("/api/health").json()

    assert "git_sha" in body
    assert body["git_sha"]


def test_readiness_is_degraded_when_the_database_is_unreachable(client: TestClient) -> None:
    """503 so a load balancer drains the instance instead of serving errors."""
    response = client.get("/api/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["database"] == "unreachable"


def test_readiness_does_not_leak_the_connection_string(client: TestClient) -> None:
    """`detail` carries an exception class name, never credentials."""
    body = client.get("/api/health/ready").json()

    assert body["detail"]
    assert "nobody" not in body["detail"]
    assert "127.0.0.1" not in body["detail"]


def test_openapi_schema_is_served_under_the_api_prefix(client: TestClient) -> None:
    """Caddy proxies /api/*; the schema has to live there or docs 404 in dev."""
    response = client.get("/api/openapi.json")

    assert response.status_code == 200
    assert "/api/health" in response.json()["paths"]


@pytest.mark.integration
def test_readiness_is_ready_against_real_postgres(db_client: TestClient) -> None:
    """The happy path, exercised in CI against a service container."""
    response = db_client.get("/api/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["database"] == "ok"
    assert body["detail"] is None
