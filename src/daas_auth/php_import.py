"""
Copy PHP's rows into this service's database (`daas-auth import-php`).
"""

import sqlalchemy as sa
from alembic.runtime.migration import MigrationContext
from sqlalchemy.engine import Connection

# PHP's 8 tables. Parents first, so every foreign key finds its row.
TABLES = (
    "users",
    "user_groups",
    "desktops",
    "desktop_groups",
    "oauth2_clients",
    "users_to_user_groups",
    "desktops_to_desktop_groups",
    "desktopgroup_usergroup",
)


class ImportRefused(Exception):
    """
    The import would not give a clean copy, so nothing was written.
    """


def import_php(source: Connection, target: Connection) -> dict[str, int]:
    """
    Copy every row of the 8 tables, with PHP's ids. Returns the rows per table.
    """
    # The import fits only 0001 schema; later migrations then change the rows.
    revision = MigrationContext.configure(target).get_current_revision()
    if revision != "0001":
        raise ImportRefused(f"DB must be at revision 0001, it is at {revision}")
    # Nothing in PHP's database may change: the session can only read.
    source.exec_driver_sql("SET SESSION TRANSACTION READ ONLY")
    source.commit()

    copied: dict[str, int] = {}
    for name in TABLES:
        # Reflection: read each table's columns from the database itself.
        php_table = sa.Table(name, sa.MetaData(), autoload_with=source)
        new_table = sa.Table(name, sa.MetaData(), autoload_with=target)
        if php_table.columns.keys() != new_table.columns.keys():
            raise ImportRefused(f"{name}: PHP's columns differ from 0001's")
        if target.execute(
            sa.select(sa.func.count()).select_from(new_table)
        ).scalar_one():
            raise ImportRefused(f"{name} is not empty")
        rows = source.execute(sa.select(php_table)).mappings().all()
        if rows:
            target.execute(sa.insert(new_table), [dict(row) for row in rows])
        copied[name] = len(rows)
    target.commit()  # all 8 tables or none
    return copied
