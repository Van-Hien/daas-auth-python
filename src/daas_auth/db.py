"""
The connection to the database. Built once, at startup.
"""

from typing import Any

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import URL, Connection, Engine

# The connections one engine opens to MariaDB:
# POOL_SIZE connections are kept open and reused by every request.
# Under load, up to MAX_OVERFLOW extra connections are opened, and closed again
# once they are no longer needed.
POOL_SIZE = 5
MAX_OVERFLOW = 10

# The most connections that can be in use at once. app.py lets only this many
# requests hold a database session, so no request ever has to wait inside a
# worker thread for a free connection. Even though 5 and 10 are SQLAlchemy's defaults;
# they are written out so that app.py can use the same total.
DB_CONNECTIONS = POOL_SIZE + MAX_OVERFLOW


def make_engine(database_url: str | URL) -> Engine:
    # pool_pre_ping: test a pooled connection before use, so a restarted
    # MariaDB costs one retry instead of an error for the caller.
    if sa.make_url(database_url).get_backend_name() == "sqlite":
        # SQLite in memory uses a pool without these two settings; a SQLite file
        # gets SQLAlchemy's defaults, which are the same two numbers.
        return sa.create_engine(database_url, pool_pre_ping=True)
    return sa.create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
    )


def check_strict_mode(connection: Connection) -> None:
    """
    Refuse a MariaDB session that would store invalid input (N-1).

    Without STRICT_ALL_TABLES, MariaDB cuts a too-long value and only warns.
    SQLite has no sql_mode, so the check is skipped there.
    """
    if connection.dialect.name not in ("mysql", "mariadb"):
        return
    sql_mode = connection.exec_driver_sql("SELECT @@SESSION.sql_mode").scalar_one()
    if "STRICT_ALL_TABLES" not in str(sql_mode).split(","):
        raise RuntimeError(f"MariaDB session is not strict: sql_mode={sql_mode!r}")


def enforce_foreign_keys(engine: Engine) -> None:
    """
    SQLite checks foreign keys only when each connection asks; MariaDB always does.
    For the service only: Alembic's table rebuilds on SQLite need them off.
    """
    if engine.dialect.name != "sqlite":
        return

    @event.listens_for(engine, "connect")
    def foreign_keys_on(dbapi_connection: Any, _: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()
