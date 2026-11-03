"""version link tables: the three group link tables keep their history on MariaDB

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-03 23:15:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Who may use which desktop is decided by these rows, so who changed them stays known.
TABLES = (
    "users_to_user_groups",
    "desktops_to_desktop_groups",
    "desktopgroup_usergroup",
)


def upgrade() -> None:
    if op.get_bind().dialect.name in ("mysql", "mariadb"):
        # N-2: MariaDB keeps every old version of a row. SQLite has no such thing.
        for table in TABLES:
            op.execute(f"ALTER TABLE {table} ADD SYSTEM VERSIONING")


def downgrade() -> None:
    if op.get_bind().dialect.name in ("mysql", "mariadb"):
        # The old versions go with it: back to 0011 means without history.
        for table in TABLES:
            op.execute(f"ALTER TABLE {table} DROP SYSTEM VERSIONING")
