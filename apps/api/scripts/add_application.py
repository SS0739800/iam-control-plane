"""Add an application that has no SAML metadata to paste.

    python -m scripts.add_application hrms "HRMS" --protocol scim2

Why this exists
---------------

``POST /api/applications`` registers a SAML service provider: it requires a metadata
document, reads an entity id and a reply URL out of it, and exists so applications
can be signed into. That is the right shape for most of them.

It is the wrong shape for an application we only *provision into*. The HRMS accepts
SCIM pushes and has no SSO at all, so there is no metadata to paste and no entity id
to read — but there is still a real application, with real access to grant, and
somebody has to be able to create it.

``AppProtocol`` has had ``scim2`` and ``none`` since P1 for exactly this, and until
now the only thing that ever created such a row was ``scripts.seed``. That is fine
locally and useless in production, where running the seed would add 1,284 fictional
employees to a real directory.

So this is the third gap of the same family that deploying turned up, after the
identity-provider bootstrap and the ``BASE_URL`` default. The pattern is worth
naming: every one of them was a path that existed only through seed data, and none
of them was visible until a database started empty.

What it does not do
-------------------

It does not grant anybody access. An application with nobody assigned provisions
nobody, which is the correct starting state — access is a separate decision, made in
the console where it is recorded as one.

It also does not touch a SAML application. If the slug already exists and carries an
entity id, this refuses rather than quietly converting somebody's SSO integration
into a provision-only row.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit import AuditDraft, append_event
from iam.config import get_settings
from iam.db import build_engine, build_sessionmaker
from iam.models.application import Application
from iam.models.enums import ActorType, AppProtocol, AppStatus, AuditOutcome

ACTOR_LABEL = "scripts.add_application (bootstrap)"

# saml2 is deliberately absent. A SAML application needs an entity id and a reply URL
# read out of a metadata document, and inventing one here would produce a row that
# looks registered and cannot be signed into.
ALLOWED = (AppProtocol.SCIM2, AppProtocol.NONE, AppProtocol.OIDC)


class Refused(Exception):
    """Why we are not doing it."""


async def add(
    session: AsyncSession,
    *,
    slug: str,
    name: str,
    protocol: AppProtocol,
    description: str | None,
) -> Application:
    """Create the application, or refuse and say why.

    Raises:
        Refused: The slug or name is taken, or the existing row is a SAML
            registration this should not be overwriting.
    """
    existing = await session.scalar(select(Application).where(Application.slug == slug))
    if existing is not None:
        if existing.entity_id:
            raise Refused(
                f"{slug!r} already exists and is a SAML application "
                f"({existing.entity_id}). Registering it again belongs in the console, "
                "where pasting new metadata updates it."
            )
        raise Refused(
            f"{slug!r} already exists ({existing.name}, {existing.protocol}). " "Nothing to do."
        )

    # Names are unique too, and a clash here is a worse error message later.
    clash = await session.scalar(select(Application).where(Application.name == name))
    if clash is not None:
        raise Refused(f"the name {name!r} is already used by {clash.slug!r}.")

    application = Application(
        slug=slug,
        name=name,
        description=description,
        protocol=protocol,
        status=AppStatus.ACTIVE,
    )
    session.add(application)
    await session.flush()

    await append_event(
        session,
        AuditDraft(
            action="application.registered",
            # Nobody did this through the console, because the console cannot: there
            # is no form for an application without SAML metadata. Saying "system"
            # keeps the log honest rather than attributing it to whoever ran it.
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            actor_label=ACTOR_LABEL,
            outcome=AuditOutcome.SUCCESS,
            target_type="application",
            target_id=str(application.id),
            target_label=application.slug,
            detail={
                "bootstrap": True,
                "protocol": str(protocol),
                "why": (
                    "created from the command line because it has no SAML metadata "
                    "and the console only registers applications from metadata"
                ),
            },
        ),
    )
    await session.commit()
    return application


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)

    try:
        protocol = AppProtocol(args.protocol)
    except ValueError:
        allowed = ", ".join(str(p) for p in ALLOWED)
        print(f"{args.protocol!r} is not a protocol. Use one of: {allowed}", file=sys.stderr)
        return 2

    if protocol not in ALLOWED:
        allowed = ", ".join(str(p) for p in ALLOWED)
        print(
            f"{protocol} needs metadata, which this cannot invent. Register it in the "
            f"console instead. This handles: {allowed}",
            file=sys.stderr,
        )
        return 2

    try:
        async with sessionmaker() as session:
            application = await add(
                session,
                slug=args.slug,
                name=args.name,
                protocol=protocol,
                description=args.description,
            )
            print(f"Added {application.slug!r} ({application.name}), protocol {protocol}.")
            print()
            print("Nobody has access to it yet, which is the right starting state.")
            print("Assign people in the console, then register a provisioning target")
            print("for it if something downstream should receive accounts.")
            return 0
    except Refused as refused:
        print(f"Not adding it: {refused}", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an application that has no SAML metadata to register from."
    )
    parser.add_argument("slug", help="Short name safe to put in a URL.")
    parser.add_argument("name", help='Display name, e.g. "HRMS".')
    parser.add_argument(
        "--protocol",
        default=str(AppProtocol.SCIM2),
        help="How it integrates: scim2 (we push accounts to it), none (we only track "
        "who has access), or oidc. Default: scim2.",
    )
    parser.add_argument("--description", default=None)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
