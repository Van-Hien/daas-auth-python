"""rename desktopgroup_usergroup columns: desktop_group_id, user_group_id

PHP named them desktopgroup_id and usergroup_id, unlike its other two link tables.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-03 01:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TABLE = "desktopgroup_usergroup"
# (old column, new column, referred table)
COLUMNS = (
    ("desktopgroup_id", "desktop_group_id", "desktop_groups"),
    ("usergroup_id", "user_group_id", "user_groups"),
)


def _rename(old_index: int, new_index: int) -> None:
    # The index and foreign key names contain the column name, so they move too.
    with op.batch_alter_table(TABLE) as batch_op:
        for names in COLUMNS:
            old, new, referred = names[old_index], names[new_index], names[2]
            batch_op.drop_constraint(
                batch_op.f(f"fk_{TABLE}_{old}_{referred}"), type_="foreignkey"
            )
            batch_op.drop_index(batch_op.f(f"ix_{TABLE}_{old}"))
            batch_op.alter_column(
                old, new_column_name=new, existing_type=ID, existing_nullable=False
            )
    with op.batch_alter_table(TABLE) as batch_op:
        for names in COLUMNS:
            new, referred = names[new_index], names[2]
            batch_op.create_index(batch_op.f(f"ix_{TABLE}_{new}"), [new])
            batch_op.create_foreign_key(
                batch_op.f(f"fk_{TABLE}_{new}_{referred}"),
                referred,
                [new],
                ["id"],
                ondelete="CASCADE",
            )


def upgrade() -> None:
    _rename(0, 1)


def downgrade() -> None:
    _rename(1, 0)
