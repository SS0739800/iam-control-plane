"""Deciding whether we are willing to send anything to an address.

This enforces ADR 0007. See that doc for why outbound provisioning is allowed
at all when ADR 0006 says we never fetch a URL somebody gives us - short
version: a provisioning target is a reviewed row, not a value in a request.

This check runs when a target is registered, not on every push. That means a
hostname that resolves somewhere harmless today and somewhere private
tomorrow won't get caught here. Resolving before every request would be
slower and still racy (DNS can change between the check and the connection),
so instead the control is that the address is a row someone chose, visible on
a page and in the audit log. This stops obvious mistakes; it's not a sandbox.

No xmlsec, no network, no database - pure string checks, so it's testable
anywhere.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BLOCKED_ALWAYS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)
"""Refused in every environment, with no setting to relax it.

Link-local addresses. Nothing legitimate is a SCIM server here, and
169.254.169.254 is the cloud metadata service - it hands out credentials to
anything that asks, so it's the most valuable target a server-side request
could reach.
"""

ALLOWED_SCHEMES = ("http", "https")


class UnusableTarget(Exception):
    """We will not send anything to that address, and the message says why."""


@dataclass(frozen=True, slots=True)
class Decision:
    """What was allowed, and what it cost.

    `concession` records a rule that was relaxed rather than met - a private
    address outside production, or plain HTTP. Kept so the target's page can
    show it was a deliberate exception, not an oversight.
    """

    host: str
    scheme: str
    concession: str | None = None


def _literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP, if the host is written as one.

    A hostname is left alone - resolving it here would look like a stronger
    check than it is (see the module docstring), and `hrms` is exactly the
    kind of name a compose target has.
    """
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def check(url: str, *, is_production: bool, allow_private: bool) -> Decision:
    """Decide whether this is somewhere we are prepared to provision into.

    Args:
        url: The target's base URL, as somebody typed it.
        is_production: Tightens two of the rules. Locally a downstream at
            ``http://hrms:8000`` is normal for compose.
        allow_private: Permit a private or loopback address in production. Never
            permits link-local.

    Returns:
        What was allowed, including any rule that was relaxed to allow it.

    Raises:
        UnusableTarget: The address is one we refuse, with the reason.
    """
    parsed = urlparse(url.strip())

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnusableTarget(
            f"{parsed.scheme or 'that'} is not an address we can provision into. "
            "It has to start with http:// or https://."
        )

    if not parsed.hostname:
        raise UnusableTarget("That address has no host in it.")

    host = parsed.hostname
    address = _literal_address(host)
    concession: str | None = None

    if address is not None:
        for network in BLOCKED_ALWAYS:
            if address.version == network.version and address in network:
                # No environment or setting can bypass this. See BLOCKED_ALWAYS.
                raise UnusableTarget(
                    f"{host} is a link-local address. Nothing legitimate is a SCIM "
                    "server there, and it is where cloud metadata services live — so "
                    "this is refused everywhere, with no setting to allow it."
                )

        private = address.is_private or address.is_loopback
        if private and is_production:
            if not allow_private:
                raise UnusableTarget(
                    f"{host} is a private address, which is refused in production. "
                    "A downstream on an internal address there is more likely a "
                    "mistake than an intention. Set "
                    "ALLOW_PRIVATE_PROVISIONING_TARGETS if it really is one."
                )
            concession = f"{host} is a private address, allowed by configuration"

    if parsed.scheme == "http":
        if is_production:
            raise UnusableTarget(
                "That address is plain HTTP. A bearer token that can write to "
                "somebody else's directory should not cross a network in the clear, "
                "so production requires https://."
            )
        concession = "plain HTTP, which is only allowed outside production"

    if concession:
        logger.info("provisioning.target_concession", extra={"host": host, "why": concession})

    return Decision(host=host, scheme=parsed.scheme, concession=concession)
