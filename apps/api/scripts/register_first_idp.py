"""Register the first identity provider, on a database that has none.

    python -m scripts.register_first_idp okta "Okta" ./okta-idp.xml

Why this exists
---------------

A fresh deployment cannot let anybody in, and the reason is a loop:

- ``POST /api/identity-providers`` needs ``idp:write``, which only an admin has.
- Becoming an admin needs ``scripts.grant_first_admin``, which grants to a user that
  already exists.
- Users are only created by logging in.
- Logging in needs a registered identity provider.

There is no password authentication anywhere, on purpose, so no hand-made row breaks
the loop either — an admin who cannot authenticate is not a way in. The first
provider has to be registered out of band or not at all.

``grant_first_admin`` closed the analogous gap one step further along, and the
deploy runbook then said "POST it to /api/identity-providers", which is not
something a new deployment can do. This is the missing step, found by trying to
follow the runbook on a real deployment.

Why it does not refuse to run twice
-----------------------------------

Unlike ``grant_first_admin``, which is a genuine backdoor if it keeps working, this
grants nobody anything. It stores the public half of a provider's SAML metadata — an
entity id, two URLs and a signing certificate — and an operator who can already run
commands inside the container is not being handed new authority by it.

It does refuse to *replace* an existing provider without ``--replace``, because
overwriting the certificate a working login depends on should be deliberate. Use the
console for rotations once somebody can reach it: the endpoint records the old and
new fingerprints, which this cannot do as usefully.

The audit entry
---------------

Written as ``actor_type=system`` with ``bootstrap: true`` in the detail, the same
shape ``grant_first_admin`` uses. Every other provider registration on the log has a
person behind it; this one has nobody, and the log should say so rather than
inventing an actor.
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit import AuditDraft, append_event
from iam.config import get_settings
from iam.db import build_engine, build_sessionmaker
from iam.models.enums import ActorType, AuditOutcome
from iam.models.saml import IdentityProvider
from iam.saml.metadata import (
    UnreadableMetadata,
    certificate_fingerprint,
    read_idp_metadata,
)

ACTOR_LABEL = "scripts.register_first_idp (bootstrap)"


class Refused(Exception):
    """Why we are not doing it."""


async def register(
    session: AsyncSession,
    *,
    slug: str,
    name: str,
    metadata_xml: str,
    replace: bool,
) -> IdentityProvider:
    """Store what a provider's metadata says about it.

    Goes through the same reader the endpoint uses, so a document this accepts is one
    the console would have accepted, and a document it rejects fails here rather than
    at the first login.

    Raises:
        Refused: The metadata is unusable, the slug is taken and --replace was not
            given, or another slug already claims the same entity id.
    """
    try:
        metadata = read_idp_metadata(metadata_xml)
    except UnreadableMetadata as exc:
        raise Refused(f"that metadata could not be used: {exc}") from exc

    existing = await session.scalar(select(IdentityProvider).where(IdentityProvider.slug == slug))
    if existing is not None and not replace:
        raise Refused(
            f"{slug!r} is already registered, pointing at {existing.entity_id}. "
            "Pass --replace to overwrite it, or rotate through the console, which "
            "records the old and new certificate fingerprints."
        )

    # The same guard the endpoint has. Two slugs for one provider makes logins
    # ambiguous: an assertion names the entity that issued it, not which of our rows
    # to check it against.
    clash = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.entity_id == metadata.entity_id,
            IdentityProvider.slug != slug,
        )
    )
    if clash is not None:
        raise Refused(
            f"{metadata.entity_id} is already registered as {clash.slug!r}. "
            "Update that one instead of adding a second name for it."
        )

    previous = certificate_fingerprint(existing.signing_cert) if existing else None

    provider = existing or IdentityProvider(slug=slug)
    provider.name = name
    provider.enabled = True
    provider.want_signed_assertions = True
    provider.entity_id = metadata.entity_id
    provider.sso_url = metadata.sso_url
    provider.slo_url = metadata.slo_url
    provider.signing_cert = metadata.signing_cert

    if existing is None:
        session.add(provider)
    await session.flush()

    fingerprint = certificate_fingerprint(metadata.signing_cert)
    await append_event(
        session,
        AuditDraft(
            action="idp.updated" if existing else "idp.registered",
            # Nobody did this. There is no admin yet — that is the whole reason this
            # script exists — so inventing an actor would put a lie on the log.
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            actor_label=ACTOR_LABEL,
            outcome=AuditOutcome.SUCCESS,
            target_type="identity_provider",
            target_id=str(provider.id),
            target_label=provider.slug,
            detail={
                "bootstrap": True,
                "entity_id": provider.entity_id,
                "sso_url": provider.sso_url,
                "certificate_fingerprint": fingerprint,
                "previous_certificate_fingerprint": previous,
                "why": (
                    "registered from the command line because a new deployment has "
                    "no admin who could do it through the console"
                ),
            },
        ),
    )
    await session.commit()
    return provider


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)

    try:
        xml = pathlib.Path(args.metadata).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Could not read {args.metadata}: {exc}", file=sys.stderr)
        return 2

    try:
        async with sessionmaker() as session:
            total = await session.scalar(select(func.count()).select_from(IdentityProvider))
            provider = await register(
                session,
                slug=args.slug,
                name=args.name,
                metadata_xml=xml,
                replace=args.replace,
            )

            print(f"Registered {provider.slug!r} ({provider.name})")
            print(f"  entity id: {provider.entity_id}")
            print(f"  sso url:   {provider.sso_url}")
            print(f"  slo url:   {provider.slo_url or '(none advertised)'}")
            print(f"  cert:      {certificate_fingerprint(provider.signing_cert)}")
            print()
            base = settings.base_url.rstrip("/")
            print(f"Log in at: {base}/saml/login?idp={provider.slug}")
            if total == 0:
                # The reason this script exists, said out loud at the moment it stops
                # being true.
                print(
                    "\nThat was the first provider on this deployment, so somebody "
                    "can now log in.\nThe first person to do so becomes an ordinary "
                    "employee with no console\npermissions — run "
                    "scripts.grant_first_admin afterwards to change that."
                )
            return 0
    except Refused as refused:
        print(f"Not registering it: {refused}", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Register an identity provider from its metadata, without needing "
        "an admin to exist first."
    )
    parser.add_argument("slug", help="Short name used in /saml/login?idp=<slug>.")
    parser.add_argument("name", help='Display name, e.g. "Okta".')
    parser.add_argument("metadata", help="Path to the provider's metadata XML.")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Overwrite an existing provider with this slug. Prefer the console for "
        "rotations, which records both certificate fingerprints.",
    )
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
