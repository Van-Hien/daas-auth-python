"""The connection to the database. Built once, at startup."""

import sqlalchemy as sa
from sqlalchemy.engine import URL, Connection, Engine


def make_engine(database_url: str | URL) -> Engine:
    # pool_pre_ping: test a pooled connection before use, so a restarted
    # MariaDB costs one retry instead of an error for the caller.
    return sa.create_engine(database_url, pool_pre_ping=True)


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
