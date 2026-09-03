"""Sending email, for the access request notifications.

Nothing here is allowed to fail a request. If somebody approves an access grant
and the mail server is down, the grant still happens and the approval is still
recorded — the notification is a courtesy. So every function catches its own
errors and returns whether it managed to send, instead of raising. That's the
opposite of the audit log, where a failure has to abort since the audit entry
is the record itself, not a copy of one.

``smtplib`` is synchronous, so sending runs in a worker thread via
``asyncio.to_thread`` instead of blocking the event loop for as long as the mail
server takes to answer.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from iam.config import Settings

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 10
"""How long to wait on the mail server before giving up.

Kept short since a notification nobody is waiting for isn't worth holding a
worker thread for.
"""


@dataclass(frozen=True, slots=True)
class Mail:
    """One message, ready to send."""

    to: tuple[str, ...]
    subject: str
    body: str

    @property
    def recipients(self) -> tuple[str, ...]:
        """Addresses with the obvious rubbish removed.

        Drops blanks (somebody with no email) and de-duplicates (two people
        sharing one address), since sending to a blank address errors and
        sending twice is just annoying.
        """
        seen: dict[str, None] = {}
        for address in self.to:
            cleaned = (address or "").strip()
            if cleaned and "@" in cleaned:
                seen.setdefault(cleaned.lower(), None)
        return tuple(seen)


def _build(mail: Mail, settings: Settings) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = ", ".join(mail.recipients)
    message["Subject"] = mail.subject
    message.set_content(mail.body)
    return message


def _send_blocking(message: EmailMessage, settings: Settings) -> None:
    """The actual SMTP conversation. Runs in a worker thread."""
    with smtplib.SMTP(
        settings.smtp_host, settings.smtp_port, timeout=SEND_TIMEOUT_SECONDS
    ) as server:
        if settings.smtp_use_tls:
            server.starttls()
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


async def send(mail: Mail, settings: Settings) -> bool:
    """Try to send one message. Returns whether it went.

    Never raises. A caller that cares can check the return value; most don't.
    """
    if not mail.recipients:
        # "Nobody to notify" usually means the approvers have no email
        # addresses, which somebody should fix.
        logger.warning("mail.no_recipients", extra={"subject": mail.subject})
        return False

    if not settings.mail_enabled:
        logger.info(
            "mail.suppressed",
            extra={
                "to": list(mail.recipients),
                "subject": mail.subject,
                "detail": "MAIL_ENABLED is false, so this was logged instead of sent.",
            },
        )
        return False

    try:
        await asyncio.to_thread(_send_blocking, _build(mail, settings), settings)
    except (OSError, smtplib.SMTPException) as exc:
        # Caught, not raised: the decision this message describes is already
        # recorded, so failing here would undo nothing but lose the notice.
        logger.warning(
            "mail.send_failed",
            extra={
                "to": list(mail.recipients),
                "subject": mail.subject,
                "error": str(exc),
                "host": f"{settings.smtp_host}:{settings.smtp_port}",
            },
        )
        return False

    logger.info("mail.sent", extra={"to": list(mail.recipients), "subject": mail.subject})
    return True
