"""
Add communication preference columns to the user table.

SQLModel create_all() does not alter existing tables. Run this after pulling
#189 changes if your local or deployed database predates comm_opt_in columns.

Usage:
    uv run python -m migrations.add_communication_preferences .env
    uv run python -m migrations.add_communication_preferences .env --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import Session, create_engine

from utils.core.db import get_connection_url

COLUMNS = ("comm_opt_in", "comm_updates", "comm_marketing")


@dataclass
class MigrationStats:
    missing_columns: tuple[str, ...] = ()
    all_present: bool = False


def _column_exists(session: Session, column_name: str) -> bool:
    result = session.connection().execute(
        text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'user'
              AND column_name = :column_name
            """
        ),
        {"column_name": column_name},
    )
    return result.first() is not None


def add_communication_preference_columns(env_file: str, apply: bool) -> MigrationStats:
    load_dotenv(env_file, override=True)
    engine = create_engine(get_connection_url())
    stats = MigrationStats()

    try:
        with Session(engine) as session:
            missing = tuple(
                column for column in COLUMNS if not _column_exists(session, column)
            )
            stats.missing_columns = missing
            stats.all_present = not missing

            if apply and missing:
                session.connection().execute(
                    text(
                        """
                        ALTER TABLE "user"
                          ADD COLUMN IF NOT EXISTS comm_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
                          ADD COLUMN IF NOT EXISTS comm_updates BOOLEAN NOT NULL DEFAULT FALSE,
                          ADD COLUMN IF NOT EXISTS comm_marketing BOOLEAN NOT NULL DEFAULT FALSE
                        """
                    )
                )
                session.commit()
            else:
                session.rollback()
    finally:
        engine.dispose()

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Add comm_opt_in, comm_updates, and comm_marketing to the user table. "
            "Without --apply, runs in dry-run mode."
        )
    )
    parser.add_argument("env", help="Env file to use (e.g. .env)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the schema change (default is dry-run).",
    )
    args = parser.parse_args()

    stats = add_communication_preference_columns(
        env_file=args.env, apply=args.apply
    )
    mode = "APPLY" if args.apply else "DRY-RUN"
    if stats.all_present:
        print(f"[{mode}] All communication preference columns already exist.")
        return

    print(f"[{mode}] missing_columns={list(stats.missing_columns)}")
    if args.apply:
        print(f"[{mode}] Columns added successfully.")
    else:
        print("Dry-run only. Re-run with --apply to add columns.")


if __name__ == "__main__":
    main()
