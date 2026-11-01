"""drop users role: user_roles is now the only source of a user's role

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-01 00:35:28.265304

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


KEEP_USERS = {"sqlite_autoincrement": True}


def upgrade() -> None:
    # user_roles is now the only place that says who is an admin.
    with op.batch_alter_table("users", table_kwargs=KEEP_USERS) as batch:
        batch.drop_column("role")


def downgrade() -> None:
    with op.batch_alter_table("users", table_kwargs=KEEP_USERS) as batch:
        batch.add_column(sa.Column("role", sa.String(16)))
    # Back to one string per user: admin if the user holds that role.
    users = sa.table("users", sa.column("id"), sa.column("role"))
    user_roles = sa.table("user_roles", sa.column("user_id"), sa.column("role_id"))
    roles = sa.table("roles", sa.column("id"), sa.column("name"))
    is_admin = (
        sa.exists()
        .where(user_roles.c.user_id == users.c.id)
        .where(user_roles.c.role_id == roles.c.id)
        .where(roles.c.name == "admin")
    )
    op.execute(users.update().values(role=sa.case((is_admin, "admin"), else_="user")))
    with op.batch_alter_table("users", table_kwargs=KEEP_USERS) as batch:
        batch.alter_column("role", existing_type=sa.String(16), nullable=False)
