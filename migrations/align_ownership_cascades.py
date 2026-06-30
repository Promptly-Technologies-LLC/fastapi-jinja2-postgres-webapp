"""
Align ownership-style foreign keys with database-level delete cascades.

Required when upgrading from <=1.0.1 to >1.0.1. if AccountEmail,
UserAvatar, or OrganizationResource tables were created without ON DELETE
CASCADE. SQLModel create_all() applies this for new databases but does not
alter existing constraints.

Usage:
    uv run python -m migrations.align_ownership_cascades .env
    uv run python -m migrations.align_ownership_cascades .env --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import Session, create_engine

from utils.core.db import get_connection_url


@dataclass(frozen=True)
class ForeignKeyTarget:
    source_schema: str
    source_table: str
    source_column: str
    target_schema: str
    target_table: str
    target_column: str
    constraint_name: str

    @property
    def label(self) -> str:
        return f"{self.source_schema}.{self.source_table}.{self.source_column}"


@dataclass
class MigrationStats:
    already_cascading: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()
    skipped_missing_tables: tuple[str, ...] = ()


TARGETS = (
    ForeignKeyTarget(
        source_schema="private",
        source_table="accountemail",
        source_column="account_id",
        target_schema="private",
        target_table="account",
        target_column="id",
        constraint_name="fk_accountemail_account_id_account",
    ),
    ForeignKeyTarget(
        source_schema="public",
        source_table="useravatar",
        source_column="user_id",
        target_schema="public",
        target_table="user",
        target_column="id",
        constraint_name="fk_useravatar_user_id_user",
    ),
    ForeignKeyTarget(
        source_schema="public",
        source_table="organizationresource",
        source_column="organization_id",
        target_schema="public",
        target_table="organization",
        target_column="id",
        constraint_name="fk_organizationresource_organization_id_organization",
    ),
)


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _qualified_table(schema: str, table: str) -> str:
    return f"{_quote_identifier(schema)}.{_quote_identifier(table)}"


def _table_exists(session: Session, schema: str, table: str) -> bool:
    result = session.connection().execute(
        text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = :schema
              AND table_name = :table
            """
        ),
        {"schema": schema, "table": table},
    )
    return result.first() is not None


def _matching_foreign_keys(
    session: Session, target: ForeignKeyTarget
) -> list[tuple[str, str]]:
    result = session.connection().execute(
        text(
            """
            SELECT tc.constraint_name, rc.delete_rule
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
              ON kcu.constraint_schema = tc.constraint_schema
             AND kcu.constraint_name = tc.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu
              ON ccu.constraint_schema = tc.constraint_schema
             AND ccu.constraint_name = tc.constraint_name
            JOIN information_schema.referential_constraints AS rc
              ON rc.constraint_schema = tc.constraint_schema
             AND rc.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_schema = :source_schema
              AND tc.table_name = :source_table
              AND kcu.column_name = :source_column
              AND ccu.table_schema = :target_schema
              AND ccu.table_name = :target_table
              AND ccu.column_name = :target_column
            ORDER BY tc.constraint_name
            """
        ),
        {
            "source_schema": target.source_schema,
            "source_table": target.source_table,
            "source_column": target.source_column,
            "target_schema": target.target_schema,
            "target_table": target.target_table,
            "target_column": target.target_column,
        },
    )
    return [(row.constraint_name, row.delete_rule) for row in result]


def _replace_foreign_key_with_cascade(
    session: Session, target: ForeignKeyTarget, existing_names: list[str]
) -> None:
    source_table = _qualified_table(target.source_schema, target.source_table)
    target_table = _qualified_table(target.target_schema, target.target_table)

    for constraint_name in existing_names:
        session.connection().execute(
            text(
                f"ALTER TABLE {source_table} "
                f"DROP CONSTRAINT {_quote_identifier(constraint_name)}"
            )
        )

    session.connection().execute(
        text(
            f"ALTER TABLE {source_table} "
            f"ADD CONSTRAINT {_quote_identifier(target.constraint_name)} "
            f"FOREIGN KEY ({_quote_identifier(target.source_column)}) "
            f"REFERENCES {target_table} ({_quote_identifier(target.target_column)}) "
            "ON DELETE CASCADE"
        )
    )


def align_ownership_cascades(env_file: str, apply: bool) -> MigrationStats:
    load_dotenv(env_file, override=True)
    engine = create_engine(get_connection_url())
    already_cascading: list[str] = []
    updated: list[str] = []
    skipped_missing_tables: list[str] = []

    try:
        with Session(engine) as session:
            for target in TARGETS:
                if not _table_exists(
                    session, target.source_schema, target.source_table
                ) or not _table_exists(
                    session, target.target_schema, target.target_table
                ):
                    skipped_missing_tables.append(target.label)
                    continue

                existing = _matching_foreign_keys(session, target)
                if len(existing) == 1 and existing[0][1] == "CASCADE":
                    already_cascading.append(target.label)
                    continue

                updated.append(target.label)
                if apply:
                    _replace_foreign_key_with_cascade(
                        session, target, [name for name, _ in existing]
                    )

            if apply:
                session.commit()
            else:
                session.rollback()
    finally:
        engine.dispose()

    return MigrationStats(
        already_cascading=tuple(already_cascading),
        updated=tuple(updated),
        skipped_missing_tables=tuple(skipped_missing_tables),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Recreate ownership-style foreign keys with ON DELETE CASCADE. "
            "Without --apply, runs in dry-run mode."
        )
    )
    parser.add_argument("env", help="Env file to use (e.g. .env)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the schema changes (default is dry-run).",
    )
    args = parser.parse_args()

    stats = align_ownership_cascades(env_file=args.env, apply=args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] already_cascading={list(stats.already_cascading)}")
    print(f"[{mode}] needs_update={list(stats.updated)}")
    if stats.skipped_missing_tables:
        print(f"[{mode}] skipped_missing_tables={list(stats.skipped_missing_tables)}")
    if args.apply and stats.updated:
        print(f"[{mode}] Foreign keys updated successfully.")
    elif not args.apply and stats.updated:
        print("Dry-run only. Re-run with --apply to recreate these foreign keys.")


if __name__ == "__main__":
    main()
