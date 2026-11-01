from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.db import make_engine
from daas_auth.domain.passwords import verify_password
from daas_auth.models import ActivityLog, OAuth2Client, Role, User, UserRole
from daas_auth.seed import SeedRefused, seed_database


@pytest.fixture
def session() -> Iterator[Session]:
    # SQLite in memory at head, the way the service would find a fresh install for test.
    engine = make_engine("sqlite://")
    with engine.connect() as connection:
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.commit()
        with Session(bind=connection) as session:
            yield session
    engine.dispose()


def test_seed_creates_the_admin_and_test_client(session: Session) -> None:
    admin_id = seed_database(
        session, email=" Admin@X.de", name="Admin", password="pw-1"
    )

    admin = session.get_one(User, admin_id)
    assert admin.email == "admin@x.de"
    assert admin.enabled
    assert verify_password("pw-1", admin.password)
    role = select(Role.name).join(UserRole).where(UserRole.user_id == admin_id)
    assert session.scalars(role).all() == ["admin"]
    client = session.get_one(OAuth2Client, "test-client")
    assert (client.is_confidential, client.secret_hash) == (False, None)
    actions = session.scalars(select(ActivityLog.action)).all()
    assert actions == ["seed", "seed"]


def test_seed_refuses_a_database_with_users(session: Session) -> None:
    seed_database(session, email="a@x.de", name="A", password="pw-1")
    with pytest.raises(SeedRefused, match="users is not empty"):
        seed_database(session, email="b@x.de", name="B", password="pw-2")
