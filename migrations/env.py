from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection

from daas_auth.config import load_migration_settings
from daas_auth.db import check_strict_mode, make_engine
from daas_auth.models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically, and keeps the loggers pytest already set up.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def prepare(connection: Connection) -> None:
    check_strict_mode(connection)
    if connection.dialect.name in ("mysql", "mariadb"):
        # Without this, MariaDB refuses ALTER TABLE on a system-versioned table (ERROR 4119).
        connection.exec_driver_sql("SET SESSION system_versioning_alter_history = KEEP")


def run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,  # SQLite can't change a column; batch mode rebuilds the table
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("Offline mode (--sql) is not used in this project.")

given = config.attributes.get("connection")
if given is not None:
    # A test hands in its own connection (SQLite in memory, or daas_auth_test)
    # and commits it itself.
    prepare(given)
    run_migrations(given)
else:
    # build engine from DAAS_MIGRATE_DATABASE_URL (database_url)
    engine = make_engine(load_migration_settings().database_url)
    with engine.connect() as connection:
        prepare(connection)
        # The check's SELECT opened a transaction. End it, or Alembic thinks the
        # caller owns it, never commits, and the alembic_version row is lost.
        connection.commit()
        run_migrations(connection)
