"""Sending email, for the access request notifications.

Best effort, on purpose
-----------------------

Nothing here is allowed to fail a request. If somebody approves an access grant
and the mail server is down, the grant still happens and the approval is still
recorded — the notification is a courtesy, and losing it must not lose the
decision. So every function catches its own errors and reports whether it managed
to send, and no caller is expected to handle a failure.

That is the opposite of how the audit log works, and the difference is
deliberate: the audit entry *is* the record, so a failure there has to abort. An
email is a copy of a record that already exists.

Blocking sockets in an async handler
------------------------------------

``smtplib`` is synchronous. Called directly from a request handler it would block
the event loop for as long as the mail server takes to answer, which on a
misbehaving server means every other request waits too. So sending runs in a
worker thread via ``asyncio.to_thread``.

The alternative is an async SMTP library, which is one more dependency for a
handful of messages a day. If this ever becomes a queue, it should become a real
background job rather than a faster socket.
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

Short. A notification nobody is waiting for is not worth holding a worker thread
for, and the failure is already harmless.
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

        An address list assembled from user records will contain blanks and
        duplicates — somebody with no email, two people sharing one. Sending to a
        blank address is an error from the server; sending twice is just rude.
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

    Never raises. A caller that cares can look at the return value; a caller that
    doesn't can ignore it, which is the common case and the reason this signature
    is a bool rather than an exception.
    """
    if not mail.recipients:
        # Worth a warning rather than silence: "nobody to notify" usually means
        # the approvers have no email addresses, which somebody should fix.
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
        # Caught, not raised. The decision this message describes has already been
        # made and recorded; failing here would undo something that worked.
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
