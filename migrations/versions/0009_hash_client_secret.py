"""
hash client secret: oauth2_clients.secret (plain text) becomes secret_hash (SHA-256)
Revision ID: 0009
Revises: 0008
Create Date: 2026-11-01 13:15:53.965138

"""

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

clients = sa.table(
    "oauth2_clients",
    sa.column("identifier"),
    sa.column("secret"),
    sa.column("secret_hash"),
    sa.column("updated_at", sa.DateTime()),
)


def upgrade() -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    with op.batch_alter_table("oauth2_clients") as batch:
        batch.add_column(sa.Column("secret_hash", sa.String(length=64), nullable=True))
    # PHP treats NULL and "" alike (PersistedClient.php:91): both mean no secret.
    rows = op.get_bind().execute(
        sa.select(clients.c.identifier, clients.c.secret).where(clients.c.secret != "")
    )
    for identifier, secret in rows.all():
        op.execute(
            clients.update()
            .where(clients.c.identifier == identifier)
            .values(
                secret_hash=hashlib.sha256(secret.encode()).hexdigest(), updated_at=now
            )
        )
    with op.batch_alter_table("oauth2_clients") as batch:
        batch.drop_column("secret")


def downgrade() -> None:
    # A hash can't be turned back into the secret: stop rather than lose it.
    hashed = op.get_bind().execute(
        sa.select(sa.func.count()).where(clients.c.secret_hash.is_not(None))
    )
    if hashed.scalar_one():
        raise RuntimeError("a client has a secret_hash; its secret can't be restored")
    with op.batch_alter_table("oauth2_clients") as batch:
        batch.add_column(sa.Column("secret", sa.String(length=200), nullable=True))
        batch.drop_column("secret_hash")
