"""php baseline

Revision ID: 0001
Revises:
Create Date: 2026-10-31 12:20:27.163407

"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

MYSQL: dict[str, Any] = {
    "mysql_engine": "InnoDB",
    # accepts emoji
    "mysql_default_charset": "utf8mb4",
    # rules for comparing, bin is comparing binary, instead of character
    "mysql_collate": "utf8mb4_bin",
    "mysql_row_format": "DYNAMIC",
}
# use BIGINT like PHP; for SQLite, use Integer
ID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", ID, primary_key=True),
        sa.Column("guid", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password", sa.String(255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("registration_code", sa.String(8)),
        sa.Column("registration_code_timeout", sa.DateTime()),
        sa.Column("registration_used_moment", sa.DateTime()),
        sa.Index("guid_idx", "guid"),
        sa.Index("registration_idx", "email", "registration_code"),
        sqlite_autoincrement=True,
        **MYSQL,
    )
    for name in ("user_groups", "desktops", "desktop_groups"):
        op.create_table(
            name,
            sa.Column("id", ID, primary_key=True),
            sa.Column("description", sa.String(255), nullable=False),
            **MYSQL,
        )
    op.create_table(
        "users_to_user_groups",
        sa.Column("user_id", ID, sa.ForeignKey("users.id"), primary_key=True),
        sa.Column(
            "user_group_id", ID, sa.ForeignKey("user_groups.id"), primary_key=True
        ),
        sa.Index(op.f("ix_users_to_user_groups_user_id"), "user_id"),
        sa.Index(op.f("ix_users_to_user_groups_user_group_id"), "user_group_id"),
        **MYSQL,
    )
    op.create_table(
        "desktops_to_desktop_groups",
        sa.Column("desktop_id", ID, sa.ForeignKey("desktops.id"), primary_key=True),
        sa.Column(
            "desktop_group_id", ID, sa.ForeignKey("desktop_groups.id"), primary_key=True
        ),
        sa.Index(op.f("ix_desktops_to_desktop_groups_desktop_id"), "desktop_id"),
        sa.Index(
            op.f("ix_desktops_to_desktop_groups_desktop_group_id"), "desktop_group_id"
        ),
        **MYSQL,
    )
    op.create_table(
        "desktopgroup_usergroup",
        sa.Column(
            "desktopgroup_id",
            ID,
            sa.ForeignKey("desktop_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "usergroup_id",
            ID,
            sa.ForeignKey("user_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Index(op.f("ix_desktopgroup_usergroup_desktopgroup_id"), "desktopgroup_id"),
        sa.Index(op.f("ix_desktopgroup_usergroup_usergroup_id"), "usergroup_id"),
        **MYSQL,
    )
    op.create_table(
        "oauth2_clients",
        sa.Column("identifier", sa.String(200), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column(
            "redirect_uris",
            sa.Text().with_variant(mysql.LONGTEXT(), "mysql", "mariadb"),
            nullable=False,
        ),
        sa.Column("is_confidential", sa.Boolean(), nullable=False),
        sa.Column("secret", sa.String(200)),
        **MYSQL,
    )


def downgrade() -> None:
    for name in (
        "desktopgroup_usergroup",
        "desktops_to_desktop_groups",
        "users_to_user_groups",
        "oauth2_clients",
        "desktop_groups",
        "user_groups",
        "desktops",
        "users",
    ):
        op.drop_table(name)
