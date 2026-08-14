"""Tests for registering the providers we accept logins from.

The one at the bottom is the point of the whole file: once a provider is
registered, /saml/login stops being a 404 and starts sending people somewhere
real, with a request the provider can read. Everything above it is about not
trusting the wrong key.

These need Postgres and skip without IAM_TEST_DATABASE_URL. No xmlsec: reading
metadata uses the standard library, which is the reason it's tested here rather
than only in the container.
"""

from __future__ import annotations

import base64
import uuid
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.models.audit import AuditEvent
from iam.models.enums import IdentitySource, PlatformRole
from iam.models.saml import IdentityProvider, SamlRequestState
from iam.models.user import User
from tests.support import run_db
from tests.test_saml_metadata import CERT_BODY, authentik_metadata, key_descriptor

pytestmark = pytest.mark.integration

ROTATED_CERT_BODY = "MIIFRotatedKeyAfterExpiry" + ("C" * 200)


@dataclass(frozen=True, slots=True)
class Console:
    """Console users for one test, one per role, with names nothing will collide with."""

    suffix: str

    @property
    def admin(self) -> str:
        return f"admin.{self.suffix}@demo.local"

    @property
    def auditor(self) -> str:
        return f"auditor.{self.suffix}@demo.local"

    @property
    def employee(self) -> str:
        return f"employee.{self.suffix}@demo.local"

    @property
    def slug(self) -> str:
        return f"authentik-{self.suffix}"

    @property
    def user_names(self) -> tuple[str, ...]:
        return (self.admin, self.auditor, self.employee)


@pytest.fixture
def console() -> Iterator[Console]:
    """Three console users and a provider slug, cleaned up afterwards."""
    made = Console(suffix=uuid.uuid4().hex[:12])

    async def create(session: AsyncSession) -> None:
        for user_name, role in (
            (made.admin, PlatformRole.ADMIN),
            (made.auditor, PlatformRole.AUDITOR),
            (made.employee, PlatformRole.EMPLOYEE),
        ):
            session.add(
                User(
                    user_name=user_name,
                    email=user_name,
                    display_name=f"{role.value.title()} {made.suffix}",
                    active=True,
                    platform_role=role,
                    source=IdentitySource.SEED,
                )
            )

    run_db(create)
    yield made

    async def tidy_up(session: AsyncSession) -> None:
        await session.execute(
            delete(SamlRequestState).where(SamlRequestState.idp_slug == made.slug)
        )
        await session.execute(delete(IdentityProvider).where(IdentityProvider.slug == made.slug))
        await session.execute(delete(User).where(User.user_name.in_(made.user_names)))

    run_db(tidy_up)


def register(
    client: TestClient,
    console: Console,
    *,
    as_user: str | None = None,
    metadata_xml: str | None = None,
    slug: str | None = None,
    **extra: object,
) -> httpx.Response:
    body: dict[str, object] = {
        "slug": slug or console.slug,
        "name": "authentik (local)",
        "metadata_xml": metadata_xml if metadata_xml is not None else authentik_metadata(),
    }
    body.update(extra)
    return client.post(
        "/api/identity-providers",
        json=body,
        headers={"X-Dev-Actor": as_user or console.admin},
    )


def latest_audit_detail(action: str) -> dict[str, object]:
    async def work(session: AsyncSession) -> dict[str, object]:
        event = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert event is not None, f"no {action} entry was written"
        detail: dict[str, object] = event.detail
        return detail

    return run_db(work)


# ------------------------------------------------------------- registering


def test_registering_reads_everything_out_of_the_metadata(
    db_client: TestClient, console: Console
) -> None:
    """None of these are fields somebody types. Letting them be typed is how you
    end up trusting a key the provider never published."""
    response = register(db_client, console)

    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"].startswith("https://authentik.demo.local/")
    assert body["sso_url"].endswith("/sso/binding/redirect/")
    assert body["slo_url"].endswith("/slo/binding/redirect/")
    assert CERT_BODY in body["signing_cert"].replace("\n", "")


def test_registering_hands_back_the_login_link(db_client: TestClient, console: Console) -> None:
    """So whoever set it up can click it and find out whether it works."""
    body = register(db_client, console).json()

    assert body["login_url"] == f"http://localhost:8080/saml/login?idp={console.slug}"


def test_registering_the_same_slug_updates_rather_than_duplicating(
    db_client: TestClient, console: Console
) -> None:
    first = register(db_client, console).json()
    second = register(db_client, console, name="authentik (renamed)").json()

    assert first["id"] == second["id"]
    assert second["name"] == "authentik (renamed)"


def test_a_certificate_rotation_is_recorded_with_both_fingerprints(
    db_client: TestClient, console: Console
) -> None:
    """A key changing when nobody rotated one is exactly the event you want to be
    able to find in a log afterwards."""
    register(db_client, console)

    rotated = authentik_metadata(keys=key_descriptor(ROTATED_CERT_BODY))
    response = register(db_client, console, metadata_xml=rotated)

    assert response.status_code == 200

    detail = latest_audit_detail("idp.updated")
    assert detail["certificate_changed"] is True
    assert detail["previous_certificate_fingerprint"] != detail["certificate_fingerprint"]


def test_re_registering_the_same_certificate_is_not_a_rotation(
    db_client: TestClient, console: Console
) -> None:
    """Otherwise every routine re-registration looks like a key change and the
    signal is worth nothing."""
    register(db_client, console)
    register(db_client, console, name="authentik (renamed)")

    assert latest_audit_detail("idp.updated")["certificate_changed"] is False


def test_a_second_name_for_the_same_provider_is_refused(
    db_client: TestClient, console: Console
) -> None:
    """An assertion says which entity issued it, not which of our rows to check it
    against, so two rows for one provider would make a login ambiguous."""
    register(db_client, console)

    response = register(db_client, console, slug=f"{console.slug}-again")

    assert response.status_code == 409
    assert "already registered" in response.json()["detail"]


# --------------------------------------------------------- metadata we refuse


def test_metadata_that_cannot_be_read_is_refused_with_the_reason(
    db_client: TestClient, console: Console
) -> None:
    """ "Could not register provider" sends somebody hunting."""
    response = register(db_client, console, metadata_xml="this is not xml")

    assert response.status_code == 400
    assert "not valid XML" in response.json()["detail"]


def test_metadata_with_no_signing_certificate_is_refused(
    db_client: TestClient, console: Console
) -> None:
    response = register(db_client, console, metadata_xml=authentik_metadata(keys=""))

    assert response.status_code == 400
    assert "signing certificate" in response.json()["detail"]


def test_a_slug_that_would_not_survive_a_query_string_is_refused(
    db_client: TestClient, console: Console
) -> None:
    """It goes in /saml/login?idp=..., so it has to be a plain word."""
    response = register(db_client, console, slug="Not A Slug")

    assert response.status_code == 422


def test_nothing_is_registered_when_the_metadata_is_bad(
    db_client: TestClient, console: Console
) -> None:
    register(db_client, console, metadata_xml="<something-else/>")

    listed = db_client.get("/api/identity-providers", headers={"X-Dev-Actor": console.admin}).json()

    assert all(provider["slug"] != console.slug for provider in listed)


# ------------------------------------------------------------ who can do this


def test_an_auditor_can_see_which_providers_are_registered(
    db_client: TestClient, console: Console
) -> None:
    """Reviewing access includes knowing where logins come from."""
    register(db_client, console)

    response = db_client.get("/api/identity-providers", headers={"X-Dev-Actor": console.auditor})

    assert response.status_code == 200
    assert any(provider["slug"] == console.slug for provider in response.json())


def test_an_auditor_cannot_register_one(db_client: TestClient, console: Console) -> None:
    """The person who reviews access shouldn't be able to change who grants it."""
    response = register(db_client, console, as_user=console.auditor)

    assert response.status_code == 403
    assert "idp:write" in response.json()["detail"]


def test_an_employee_cannot_even_look(db_client: TestClient, console: Console) -> None:
    response = db_client.get("/api/identity-providers", headers={"X-Dev-Actor": console.employee})

    assert response.status_code == 403


def test_the_list_leaves_out_the_certificate(db_client: TestClient, console: Console) -> None:
    """A wall of base64 per row makes the list unreadable. The fingerprint is what
    somebody actually wants from a list."""
    register(db_client, console)

    listed = db_client.get("/api/identity-providers", headers={"X-Dev-Actor": console.admin}).json()
    mine = next(provider for provider in listed if provider["slug"] == console.slug)

    assert "signing_cert" not in mine
    assert mine["certificate_fingerprint"]


def test_asking_for_one_provider_includes_the_certificate(
    db_client: TestClient, console: Console
) -> None:
    register(db_client, console)

    response = db_client.get(
        f"/api/identity-providers/{console.slug}", headers={"X-Dev-Actor": console.admin}
    )

    assert response.status_code == 200
    assert CERT_BODY in response.json()["signing_cert"].replace("\n", "")


def test_asking_for_a_provider_that_is_not_there_is_a_404(
    db_client: TestClient, console: Console
) -> None:
    response = db_client.get(
        "/api/identity-providers/never-registered", headers={"X-Dev-Actor": console.admin}
    )

    assert response.status_code == 404


# --------------------------------------------------- what it was all for


def test_once_registered_the_login_endpoint_sends_people_to_the_provider(
    db_client: TestClient, console: Console
) -> None:
    """The payoff. Before registering, /saml/login has no provider to use and 404s.
    After, it builds a real request and redirects, and the provider can read what
    it gets.
    """
    before = db_client.get(f"/saml/login?idp={console.slug}", follow_redirects=False)
    assert before.status_code == 404

    registered = register(db_client, console).json()

    response = db_client.get(f"/saml/login?idp={console.slug}", follow_redirects=False)

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(registered["sso_url"])

    query = parse_qs(urlparse(location).query)
    assert query["RelayState"]

    # Raw deflate, which is what the redirect binding asks for. A normal zlib
    # stream here produces a request the provider can't read.
    request_xml = zlib.decompress(
        base64.b64decode(query["SAMLRequest"][0]), -zlib.MAX_WBITS
    ).decode()
    assert 'AssertionConsumerServiceURL="http://localhost:8080/saml/acs"' in request_xml
    assert f'Destination="{registered["sso_url"]}"' in request_xml


def test_a_disabled_provider_cannot_be_logged_in_with(
    db_client: TestClient, console: Console
) -> None:
    """Turning one off stops new logins without losing its settings."""
    register(db_client, console, enabled=False)

    response = db_client.get(f"/saml/login?idp={console.slug}", follow_redirects=False)

    assert response.status_code == 404
