"""Logging, one JSON object per line.

That's the format log collectors want, which matters in P7 when logs go somewhere
other than a terminal. Easier to set up now than to convert later.
"""

from __future__ import annotations

import logging
import sys

from pythonjsonlogger.json import JsonFormatter

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# uvicorn installs its own handlers; without this they double-print alongside
# ours, once as JSON and once as plain text.
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


def configure_logging(level: str = "INFO") -> None:
    """Install a JSON formatter on the root logger. Idempotent."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter(
            _LOG_FORMAT,
            rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
            timestamp=False,
        )
    )

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    for name in _UVICORN_LOGGERS:
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
