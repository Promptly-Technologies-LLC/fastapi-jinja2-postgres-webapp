"""
Add billing tables for organization-scoped Stripe subscriptions.

Usage:
    uv run python -m migrations.add_billing_tables .env
    uv run python -m migrations.add_billing_tables .env --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import Session, create_engine

from utils.core.db import get_connection_url

TABLES = ("organizationbilling", "stripewebhookevent")


@dataclass
class MigrationStats:
    missing_tables: tuple[str, ...] = ()
    all_present: bool = False


def _table_exists(session: Session, table_name: str) -> bool:
    result = session.connection().execute(
        text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = :table_name
            """
        ),
        {"table_name": table_name},
    )
    return result.first() is not None


def add_billing_tables(env_file: str, apply: bool) -> MigrationStats:
    load_dotenv(env_file, override=True)
    engine = create_engine(get_connection_url())
    stats = MigrationStats()

    try:
        with Session(engine) as session:
            missing = tuple(
                table for table in TABLES if not _table_exists(session, table)
            )
            stats.missing_tables = missing
            stats.all_present = not missing

            if apply and missing:
                session.connection().execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS organizationbilling (
                            id SERIAL PRIMARY KEY,
                            organization_id INTEGER NOT NULL UNIQUE REFERENCES organization(id) ON DELETE CASCADE,
                            stripe_customer_id VARCHAR,
                            stripe_subscription_id VARCHAR,
                            status VARCHAR NOT NULL DEFAULT 'none',
                            price_id VARCHAR,
                            current_period_start TIMESTAMP,
                            current_period_end TIMESTAMP,
                            last_payment_at TIMESTAMP,
                            cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
                            created_at TIMESTAMP NOT NULL,
                            updated_at TIMESTAMP NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ix_organizationbilling_organization_id
                            ON organizationbilling (organization_id);
                        CREATE INDEX IF NOT EXISTS ix_organizationbilling_stripe_customer_id
                            ON organizationbilling (stripe_customer_id);
                        CREATE INDEX IF NOT EXISTS ix_organizationbilling_stripe_subscription_id
                            ON organizationbilling (stripe_subscription_id);
                        CREATE INDEX IF NOT EXISTS ix_organizationbilling_status
                            ON organizationbilling (status);

                        CREATE TABLE IF NOT EXISTS stripewebhookevent (
                            id SERIAL PRIMARY KEY,
                            stripe_event_id VARCHAR NOT NULL UNIQUE,
                            processed_at TIMESTAMP NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ix_stripewebhookevent_stripe_event_id
                            ON stripewebhookevent (stripe_event_id);
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("env_file", help="Path to .env file")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply migration (default is dry-run)",
    )
    args = parser.parse_args()
    stats = add_billing_tables(args.env_file, apply=args.apply)
    if stats.all_present:
        print("All billing tables already exist.")
        return
    print("Missing tables:", ", ".join(stats.missing_tables))
    if args.apply:
        print("Migration applied.")
    else:
        print("Dry run only. Re-run with --apply to create tables.")


if __name__ == "__main__":
    main()
