"""Write the API's OpenAPI schema to a file.

    python -m scripts.export_openapi

The frontend generates its TypeScript types from that file rather than from a
running server. So this works in CI with nothing started, and the schema is
committed, which means a pull request shows API changes as a diff instead of
hiding them.

CI runs this and then checks nothing changed. If the check fails, someone edited
the API and didn't regenerate, and the frontend types are now a lie.
"""

from __future__ import annotations

import json
from pathlib import Path

from iam.config import Settings
from iam.main import create_app

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "openapi.json"


def main() -> None:
    # Fixed settings so the output doesn't change depending on your .env. Nothing
    # here touches the database; we only ask FastAPI to describe itself.
    app = create_app(
        Settings(
            app_env="ci",
            # Not a secret. Nothing signs anything here, we only ask FastAPI to
            # describe its own routes.
            session_secret="schema-export-only",  # noqa: S106
            database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
            log_level="ERROR",
        )
    )

    schema = app.openapi()

    # sort_keys so the file doesn't churn between runs, and a trailing newline so
    # it looks like every other text file in the repo.
    OUTPUT_PATH.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT_PATH.relative_to(OUTPUT_PATH.parent.parent)}")
    print(f"  {len(schema['paths'])} paths, {len(schema['components']['schemas'])} schemas")


if __name__ == "__main__":
    main()
