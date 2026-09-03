"""Populate a development database with a believable directory.

    python -m scripts.seed --reset

Produces the counts from the original console sketch: 1,284 users, 42 groups,
17 applications (12 of them federated over SAML), and 45,829 audit events.

The random generator uses a fixed seed, so people, ids, groups and access come
out the same every run — a bookmarked user page keeps working after a reseed.
Audit timestamps are the exception: they're spread backwards from right now so
a fresh demo shows recent activity, which means the fingerprints (which include
the timestamp) differ run to run. Pass --anchor with a fixed time for
byte-identical output.

Names come from the word lists below rather than Faker, so this script needs
nothing beyond requirements.txt.

Fingerprints are computed here in Python with the same functions the app uses,
rather than calling append_event 45,829 times (which would mean 45,829 locks
and round trips), so /api/audit/verify passes on this data like it would on
real data.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import random
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import insert, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from iam.audit.chain import canonical_form, compute_hash
from iam.config import get_settings
from iam.db import build_engine, build_sessionmaker
from iam.models.application import AppAssignment, Application

# Imported from its defining module rather than through iam.audit.chain, which
# only re-exports it.
from iam.models.audit import GENESIS_HASH, AuditEvent
from iam.models.enums import (
    ActorType,
    AppProtocol,
    AppStatus,
    AuditOutcome,
    IdentitySource,
    PlatformRole,
)
from iam.models.group import Group, GroupMember
from iam.models.user import User

# ---------------------------------------------------------------- shape targets
USER_COUNT = 1_284
GROUP_COUNT = 42
AUDIT_EVENT_COUNT = 45_829
RNG_SEED = 20260813
HISTORY_DAYS = 540
"""Audit events are spread over roughly eighteen months."""

BULK_CHUNK = 5_000

DOMAIN = "demo.local"

FIRST_NAMES = (
    "Ada Alan Amara Anita Arjun Asha Beatrice Bram Carlos Chidi Clara Dmitri Elena Emeka Esther "
    "Fatima Felix Grace Hana Hugo Ingrid Isabel Ivan Jamal Jian Joan Kavya Kenji Lena Linus Lucia "
    "Mabel Mateo Mei Nadia Nikhil Nora Olga Omar Priya Rafael Rania Reza Rosa Samir Sofia Tariq "
    "Thandi Tomas Uma Viktor Wanjiru Wei Yara Yusuf Zara Zoe Bilal Carmen Dilip Freya"
).split()

FAMILY_NAMES = (
    "Abiodun Adeyemi Almeida Andersen Bakker Bergman Bhatt Calder Cardoso Chaudhry Costa Dlamini "
    "Duarte Eriksen Farouk Fernandes Gallagher Ghosh Haddad Halvorsen Ibarra Iqbal Jensen Kaur "
    "Keller Khouri Kovacs Lindqvist Lombardi Maalouf Mbeki Mendoza Moreau Nakamura Navarro Ngoma "
    "Nkemelu Okafor Oyelaran Pereira Petrov Quintero Rahman Ramirez Reyes Rossi Sandoval Sharma "
    "Silva Sorensen Tanaka Tremblay Vasquez Virtanen Wagner Wanjala Yilmaz Zhang Zimmerman Bianchi"
).split()

DEPARTMENTS = (
    "Engineering",
    "Sales",
    "Marketing",
    "Finance",
    "People",
    "Legal",
    "Support",
    "IT",
    "Product",
    "Design",
    "Operations",
    "Security",
)

JOB_TITLES = (
    "Analyst",
    "Associate",
    "Coordinator",
    "Engineer",
    "Lead",
    "Manager",
    "Specialist",
    "Director",
)

# name, slug, protocol, hrms/app role granted, description
APPLICATIONS: tuple[tuple[str, str, AppProtocol, str | None, str], ...] = (
    ("HRMS", "hrms", AppProtocol.SAML2, "Employee", "Core HR system of record"),
    ("Jira", "jira", AppProtocol.SAML2, "Member", "Issue tracking"),
    ("Confluence", "confluence", AppProtocol.SAML2, "Member", "Internal documentation"),
    ("Salesforce", "salesforce", AppProtocol.SAML2, "Standard User", "CRM"),
    ("GitHub", "github", AppProtocol.SAML2, "Member", "Source control"),
    ("AWS", "aws", AppProtocol.SAML2, "PowerUser", "Cloud infrastructure"),
    ("Slack", "slack", AppProtocol.SAML2, "Member", "Messaging"),
    ("Zoom", "zoom", AppProtocol.SAML2, "Licensed", "Video conferencing"),
    ("Workday", "workday", AppProtocol.SAML2, "Employee", "Payroll and benefits"),
    ("ServiceNow", "servicenow", AppProtocol.SAML2, "Requester", "IT service management"),
    ("Datadog", "datadog", AppProtocol.SAML2, "Read Only", "Observability"),
    ("Tableau", "tableau", AppProtocol.SAML2, "Viewer", "Business intelligence"),
    ("PagerDuty", "pagerduty", AppProtocol.SCIM2, "Responder", "On-call scheduling"),
    ("Figma", "figma", AppProtocol.SCIM2, "Editor", "Design"),
    ("Notion", "notion", AppProtocol.OIDC, "Member", "Team wiki"),
    ("Corporate VPN", "vpn", AppProtocol.NONE, None, "Network access"),
    ("Badge System", "badge", AppProtocol.NONE, None, "Physical access"),
)

ACCESS_GROUPS = (
    ("VPN Users", "Remote network access", None),
    ("GitHub Users", "Source control access", None),
    ("AWS Admins", "Production infrastructure", "Administrator"),
    ("Salesforce Users", "CRM access", None),
    ("Jira Users", "Issue tracker access", None),
    ("Datadog Viewers", "Read-only observability", None),
    ("On-Call Responders", "Paging rotation", None),
    ("Contractors", "Time-limited external staff", "Contractor"),
    ("Managers", "People-management responsibilities", "Manager"),
    ("Payroll Administrators", "Sensitive compensation data", "Payroll Admin"),
    ("Security Reviewers", "Access review participants", "Auditor"),
    ("New Starters", "Onboarding cohort", "Employee"),
)

# Weighted so the log looks like a real one: logins dominate, administrative
# changes are comparatively rare.
AUDIT_ACTIONS: tuple[tuple[str, int, str], ...] = (
    ("saml.login", 60, "user"),
    ("scim.user_updated", 12, "user"),
    ("group.member_added", 8, "group"),
    ("group.member_removed", 5, "group"),
    ("user.updated", 4, "user"),
    ("scim.user_created", 3, "user"),
    ("scim.user_deactivated", 2, "user"),
    ("app.assignment_created", 2, "application"),
    ("saml.logout", 2, "user"),
    ("audit.chain_verified", 1, "system"),
    ("authz.denied", 1, "user"),
)

PERSONAS = (
    ("admin", "Platform Admin", PlatformRole.ADMIN),
    ("helpdesk", "Helpdesk Agent", PlatformRole.HELPDESK),
    ("auditor", "Internal Auditor", PlatformRole.AUDITOR),
    ("employee", "Ordinary Employee", PlatformRole.EMPLOYEE),
)


@dataclass(frozen=True, slots=True)
class Directory:
    """Everything built up in memory before we write any of it.

    The rows are plain dicts because that's what a bulk insert wants. Building
    1,284 User objects just for SQLAlchemy to pull them apart again is wasted work.
    """

    applications: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    users: list[dict[str, Any]]
    memberships: list[dict[str, Any]]
    assignments: list[dict[str, Any]]
    managers: dict[str, uuid.UUID]
    """Department name to that department's manager. Written in a second pass, see
    link_managers."""


def _uuid(rng: random.Random) -> uuid.UUID:
    """Make a UUID from the seeded random generator.

    Don't swap this for uuid.uuid4(). That one reads system randomness, so every
    run would produce different ids and nothing about this script would repeat.
    """
    return uuid.UUID(int=rng.getrandbits(128), version=4)


async def reset(session: AsyncSession) -> None:
    """Empty every table.

    The audit log rejects DELETE and TRUNCATE, so this disables those triggers,
    truncates, and re-enables them. Shows what the append-only rule actually
    protects against: mistakes, not someone with table-owner access.
    """
    print("resetting: disabling append-only triggers on audit_events")
    await session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
    await session.execute(
        text(
            "TRUNCATE audit_events, app_assignments, group_members, "
            "applications, groups, users RESTART IDENTITY CASCADE"
        )
    )
    await session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))
    await session.commit()
    print("resetting: triggers re-enabled")


def build_directory(rng: random.Random) -> Directory:
    """Generate users, groups, applications and their relationships in memory."""
    now = dt.datetime.now(dt.UTC)

    # ------------------------------------------------------------ applications
    applications = [
        {
            "id": _uuid(rng),
            "name": name,
            "slug": slug,
            "description": description,
            "protocol": protocol,
            "status": AppStatus.ACTIVE,
            "entity_id": (
                f"https://{slug}.{DOMAIN}/saml/metadata" if protocol is AppProtocol.SAML2 else None
            ),
            "acs_url": (
                f"https://{slug}.{DOMAIN}/saml/acs" if protocol is AppProtocol.SAML2 else None
            ),
            "slo_url": (
                f"https://{slug}.{DOMAIN}/saml/sls" if protocol is AppProtocol.SAML2 else None
            ),
            "nameid_format": (
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                if protocol is AppProtocol.SAML2
                else None
            ),
        }
        for name, slug, protocol, _role, description in APPLICATIONS
    ]
    app_role = {slug: role for _n, slug, _p, role, _d in APPLICATIONS}
    app_by_slug = {row["slug"]: row for row in applications}

    # ------------------------------------------------------------------ groups
    groups: list[dict[str, Any]] = []
    for department in DEPARTMENTS:
        groups.append(
            {
                "id": _uuid(rng),
                "name": department,
                "description": f"Everyone in {department}",
                "hrms_role": "Employee",
                "external_id": f"grp-dept-{department.lower()}",
                "source": IdentitySource.SEED,
            }
        )
    for name, description, hrms_role in ACCESS_GROUPS:
        groups.append(
            {
                "id": _uuid(rng),
                "name": name,
                "description": description,
                "hrms_role": hrms_role,
                "external_id": f"grp-{name.lower().replace(' ', '-')}",
                "source": IdentitySource.SEED,
            }
        )
    # Top up to the target with per-department engineering-style teams.
    suffixes = ("Platform", "Frontend", "Data", "Infrastructure", "QA", "Mobile")
    index = 0
    while len(groups) < GROUP_COUNT:
        department = DEPARTMENTS[index % len(DEPARTMENTS)]
        suffix = suffixes[index // len(DEPARTMENTS) % len(suffixes)]
        name = f"{department} {suffix}"
        index += 1
        if any(group["name"] == name for group in groups):
            continue
        groups.append(
            {
                "id": _uuid(rng),
                "name": name,
                "description": f"{suffix} team within {department}",
                "hrms_role": "Employee",
                "external_id": f"grp-team-{name.lower().replace(' ', '-')}",
                "source": IdentitySource.SEED,
            }
        )
    groups = groups[:GROUP_COUNT]
    group_by_name = {row["name"]: row for row in groups}

    # ------------------------------------------------------------------- users
    users: list[dict[str, Any]] = []
    taken_user_names: set[str] = set()

    def make_user_name(given: str, family: str) -> str:
        base = f"{given}.{family}".lower()
        candidate = f"{base}@{DOMAIN}"
        suffix = 2
        while candidate in taken_user_names:
            candidate = f"{base}{suffix}@{DOMAIN}"
            suffix += 1
        taken_user_names.add(candidate)
        return candidate

    for slug, display, role in PERSONAS:
        user_name = f"{slug}@{DOMAIN}"
        taken_user_names.add(user_name)
        users.append(
            {
                "id": _uuid(rng),
                "external_id": f"ext-{slug}",
                "user_name": user_name,
                "email": user_name,
                "given_name": display.split()[0],
                "family_name": display.split()[-1],
                "display_name": display,
                "active": True,
                "employee_number": f"E{len(users) + 1:05d}",
                "department": "IT",
                "job_title": display,
                "manager_id": None,
                "platform_role": role,
                "source": IdentitySource.SEED,
            }
        )

    while len(users) < USER_COUNT:
        given = rng.choice(FIRST_NAMES)
        family = rng.choice(FAMILY_NAMES)
        user_name = make_user_name(given, family)
        # ~6% deactivated, so leaver flows and the active filter have something
        # real to show.
        active = rng.random() > 0.06
        users.append(
            {
                "id": _uuid(rng),
                "external_id": f"ext-{_uuid(rng).hex[:12]}",
                "user_name": user_name,
                "email": user_name,
                "given_name": given,
                "family_name": family,
                "display_name": f"{given} {family}",
                "active": active,
                "employee_number": f"E{len(users) + 1:05d}",
                "department": rng.choice(DEPARTMENTS),
                "job_title": rng.choice(JOB_TITLES),
                "manager_id": None,
                "platform_role": PlatformRole.EMPLOYEE,
                "source": IdentitySource.SCIM if rng.random() < 0.8 else IdentitySource.MANUAL,
            }
        )

    # Managers: one per department, drawn from that department's own staff, so the
    # org chart is coherent rather than random.
    by_department: dict[str, list[dict[str, Any]]] = {}
    for user in users:
        by_department.setdefault(str(user["department"]), []).append(user)

    managers: dict[str, uuid.UUID] = {}
    for department, members in by_department.items():
        candidates = [member for member in members if member["active"]]
        if not candidates:
            continue
        manager = candidates[0]
        manager["job_title"] = "Director"
        managers[department] = manager["id"]
        for member in members:
            if member["id"] != manager["id"]:
                member["manager_id"] = manager["id"]

    # -------------------------------------------------------------- membership
    memberships: list[dict[str, Any]] = []
    seen_pairs: set[tuple[uuid.UUID, uuid.UUID]] = set()

    def join(group_row: dict[str, Any], user_row: dict[str, Any]) -> None:
        pair = (group_row["id"], user_row["id"])
        if pair in seen_pairs:
            return
        seen_pairs.add(pair)
        memberships.append({"group_id": group_row["id"], "user_id": user_row["id"]})

    for user in users:
        join(group_by_name[str(user["department"])], user)
        if rng.random() < 0.75:
            join(group_by_name["VPN Users"], user)
        if user["department"] in {"Engineering", "Product", "Security"} and rng.random() < 0.85:
            join(group_by_name["GitHub Users"], user)
        if user["department"] == "Sales" and rng.random() < 0.9:
            join(group_by_name["Salesforce Users"], user)
        if user["job_title"] == "Director":
            join(group_by_name["Managers"], user)
        # A couple of extra team groups each, for realistic overlap.
        for group in rng.sample(groups, k=rng.randint(0, 2)):
            join(group, user)

    # ------------------------------------------------------------- assignments
    assignments: list[dict[str, Any]] = []

    def assign_group(group_name: str, slug: str) -> None:
        assignments.append(
            {
                "id": _uuid(rng),
                "application_id": app_by_slug[slug]["id"],
                "user_id": None,
                "group_id": group_by_name[group_name]["id"],
                "role": app_role[slug],
            }
        )

    # Everyone gets the HR systems through their department group.
    for department in DEPARTMENTS:
        assign_group(department, "hrms")
        assign_group(department, "slack")
        assign_group(department, "zoom")
        assign_group(department, "workday")

    assign_group("GitHub Users", "github")
    assign_group("AWS Admins", "aws")
    assign_group("Salesforce Users", "salesforce")
    assign_group("Jira Users", "jira")
    assign_group("Jira Users", "confluence")
    assign_group("Datadog Viewers", "datadog")
    assign_group("On-Call Responders", "pagerduty")
    assign_group("VPN Users", "vpn")
    assign_group("Managers", "tableau")
    assign_group("Engineering", "figma")
    assign_group("Design", "figma")
    assign_group("IT", "servicenow")
    assign_group("Engineering", "notion")

    # A handful of direct grants, which is what makes "why does this person have
    # access?" a non-trivial question on the user detail page.
    for user in rng.sample([u for u in users if u["active"]], k=40):
        slug = rng.choice(["tableau", "datadog", "figma", "notion", "aws"])
        assignments.append(
            {
                "id": _uuid(rng),
                "application_id": app_by_slug[slug]["id"],
                "user_id": user["id"],
                "group_id": None,
                "role": app_role[slug],
            }
        )

    print(
        f"generated: {len(users)} users, {len(groups)} groups, "
        f"{len(applications)} applications, {len(memberships)} memberships, "
        f"{len(assignments)} assignments"
    )
    _ = now
    return Directory(
        applications=applications,
        groups=groups,
        users=users,
        memberships=memberships,
        assignments=assignments,
        managers=managers,
    )


def build_audit_events(
    rng: random.Random,
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    applications: list[dict[str, Any]],
    anchor: dt.datetime,
) -> list[dict[str, Any]]:
    """Build a valid hash chain of audit events.

    Uses the application's own :func:`canonical_form` and :func:`compute_hash`, so
    the result verifies through the real code path rather than a seed-specific
    one. If those functions ever change, seeded data stops verifying — which is
    the correct outcome, and a test will catch it.
    """
    actions: list[str] = []
    targets: list[str] = []
    for action, weight, target_type in AUDIT_ACTIONS:
        actions.extend([action] * weight)
        targets.extend([target_type] * weight)

    start = anchor - dt.timedelta(days=HISTORY_DAYS)
    seconds_span = HISTORY_DAYS * 24 * 60 * 60

    # Ascending timestamps: the chain is ordered by id, and a log where entry 900
    # predates entry 400 would look broken to anyone reading it.
    offsets = sorted(rng.randint(0, seconds_span) for _ in range(AUDIT_EVENT_COUNT))

    idp_actor = "Upstream IdP <authentik>"
    rows: list[dict[str, Any]] = []
    prev_hash = GENESIS_HASH

    for offset in offsets:
        index = rng.randrange(len(actions))
        action = actions[index]
        target_type = targets[index]
        occurred_at = start + dt.timedelta(seconds=offset)

        if action.startswith("scim."):
            actor_type, actor_id, actor_label = ActorType.IDP, None, idp_actor
        elif action.startswith("audit."):
            actor_type, actor_id, actor_label = ActorType.SYSTEM, None, "Scheduled job"
        else:
            operator = rng.choice(users)
            actor_type = ActorType.USER
            actor_id = operator["id"]
            actor_label = f"{operator['display_name']} <{operator['user_name']}>"

        if target_type == "group":
            target = rng.choice(groups)
            target_id, target_label = str(target["id"]), str(target["name"])
        elif target_type == "application":
            target = rng.choice(applications)
            target_id, target_label = str(target["id"]), str(target["name"])
        elif target_type == "user":
            target = rng.choice(users)
            target_id, target_label = str(target["id"]), str(target["user_name"])
        else:
            target_id, target_label = None, None

        outcome = AuditOutcome.SUCCESS
        if action == "authz.denied":
            outcome = AuditOutcome.DENIED
        elif rng.random() < 0.015:
            outcome = AuditOutcome.FAILURE

        detail: dict[str, Any] = {"seeded": True}
        if action.startswith("saml."):
            detail["protocol"] = "SAML 2.0"
            detail["application"] = rng.choice(applications)["slug"]
        elif action.startswith("scim."):
            detail["protocol"] = "SCIM 2.0"

        row: dict[str, Any] = {
            "occurred_at": occurred_at,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_label": actor_label,
            "action": action,
            "outcome": outcome,
            "target_type": target_type if target_id else None,
            "target_id": target_id,
            "target_label": target_label,
            "ip_address": f"10.{rng.randint(0, 4)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            "user_agent": "Mozilla/5.0 (seed)",
            "correlation_id": _uuid(rng),
            "detail": detail,
            "prev_hash": prev_hash,
        }

        row["hash"] = compute_hash(
            prev_hash,
            canonical_form(
                occurred_at=occurred_at,
                actor_type=str(actor_type),
                actor_id=actor_id,
                actor_label=actor_label,
                action=action,
                outcome=str(outcome),
                target_type=row["target_type"],
                target_id=target_id,
                target_label=target_label,
                ip_address=row["ip_address"],
                user_agent=row["user_agent"],
                correlation_id=row["correlation_id"],
                detail=detail,
            ),
        )
        prev_hash = row["hash"]
        rows.append(row)

    print(f"generated: {len(rows)} audit events, chain head {prev_hash[:12]}...")
    return rows


async def bulk_insert(session: AsyncSession, table: Any, rows: list[dict[str, Any]]) -> None:
    """Insert in chunks. One 45k-row statement risks exhausting parameter limits."""
    if not rows:
        return
    for start in range(0, len(rows), BULK_CHUNK):
        await session.execute(insert(table), rows[start : start + BULK_CHUNK])
    await session.commit()


async def link_managers(session: AsyncSession, managers: dict[str, uuid.UUID]) -> None:
    """Fill in who reports to whom, after everyone exists.

    This can't be done during the insert. SQLAlchemy sends one statement per row,
    so Postgres checks the manager link immediately, and anyone inserted before
    their manager fails. Adding everyone first and then linking avoids caring about
    the order at all.

    Twelve UPDATEs, one per department, rather than 1,284.
    """
    for department, manager_id in managers.items():
        await session.execute(
            update(User)
            .where(User.department == department, User.id != manager_id)
            .values(manager_id=manager_id)
        )
    await session.commit()
    print(f"linked: {len(managers)} department managers")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Empty all tables first. Required if data already exists.",
    )
    parser.add_argument(
        "--anchor",
        type=dt.datetime.fromisoformat,
        default=None,
        metavar="ISO8601",
        help=(
            "Newest audit event timestamp. Defaults to now, so a fresh demo shows "
            "recent activity. Pass a fixed value for byte-identical output."
        ),
    )
    args = parser.parse_args()

    anchor: dt.datetime = args.anchor or dt.datetime.now(dt.UTC)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=dt.UTC)

    settings = get_settings()
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)

    # Not a secure random generator, and that's fine. We want the same demo data
    # every time, and a secure one can't be told to repeat itself.
    rng = random.Random(RNG_SEED)  # noqa: S311

    try:
        async with sessionmaker() as session:
            if args.reset:
                await reset(session)

            directory = build_directory(rng)
            events = build_audit_events(
                rng,
                directory.users,
                directory.groups,
                directory.applications,
                anchor,
            )

            print("inserting...")
            await bulk_insert(session, Application, directory.applications)
            await bulk_insert(session, Group, directory.groups)

            # Managers are linked afterwards — see link_managers.
            unlinked_users = [{**row, "manager_id": None} for row in directory.users]
            await bulk_insert(session, User, unlinked_users)
            await link_managers(session, directory.managers)

            await bulk_insert(session, GroupMember, directory.memberships)
            await bulk_insert(session, AppAssignment, directory.assignments)
            await bulk_insert(session, AuditEvent, events)
            print("done")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
