"""
add audit columns: created_at/_by, updated_at/_by on PHP's 8 tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-31 23:51:29.886378

"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# The same type as TIMESTAMP in models.py: microseconds on MariaDB.
TIMESTAMP = sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql", "mariadb")
# The 8 tables autogenerate detected.
TABLES = (
    "users",
    "user_groups",
    "users_to_user_groups",
    "desktops",
    "desktop_groups",
    "desktops_to_desktop_groups",
    "desktopgroup_usergroup",
    "oauth2_clients",
)
# SQLite rebuilds a table in batch mode, and the rebuild would lose AUTOINCREMENT (h).
KEEP = {"users": {"sqlite_autoincrement": True}}


def upgrade() -> None:
    # One time for every existing row, so created_at = updated_at on each (d). UTC.
    now = datetime.now(UTC).replace(tzinfo=None)
    for name in TABLES:
        # 1. Add the columns with NULL allowed: the rows already there have no value yet.
        with op.batch_alter_table(name, table_kwargs=KEEP.get(name, {})) as batch_op:
            batch_op.add_column(sa.Column("created_at", TIMESTAMP, nullable=True))
            batch_op.add_column(sa.Column("created_by", sa.BigInteger(), nullable=True))
            batch_op.add_column(sa.Column("updated_at", TIMESTAMP, nullable=True))
            batch_op.add_column(sa.Column("updated_by", sa.BigInteger(), nullable=True))
        # 2. Fill them. _by stays NULL: nobody was logged in during the import.
        table = sa.table(
            name,
            sa.column("created_at", sa.DateTime()),
            sa.column("updated_at", sa.DateTime()),
        )
        op.execute(table.update().values(created_at=now, updated_at=now))
        # 3. Every row has a value now, so NOT NULL, as the classes say.
        with op.batch_alter_table(name, table_kwargs=KEEP.get(name, {})) as batch_op:
            batch_op.alter_column("created_at", existing_type=TIMESTAMP, nullable=False)
            batch_op.alter_column("updated_at", existing_type=TIMESTAMP, nullable=False)


def downgrade() -> None:
    for name in reversed(TABLES):
        with op.batch_alter_table(name, table_kwargs=KEEP.get(name, {})) as batch_op:
            batch_op.drop_column("updated_by")
            batch_op.drop_column("updated_at")
            batch_op.drop_column("created_by")
            batch_op.drop_column("created_at")

    # ### end Alembic commands ###
