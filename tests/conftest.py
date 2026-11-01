import shutil
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from daas_auth.api.app import create_app
from daas_auth.config import Settings, load_migration_settings, load_settings
from daas_auth.db import make_engine
from daas_auth.models import Role, User, UserRole
from daas_auth.seed import seed_database

# Tests use their own database, never daas_auth, so they can't touch real rows.
TEST_DATABASE = "daas_auth_test"
# The admin every API test starts with (made by daas-auth seed, so Argon2id).
ADMIN_EMAIL = "admin@x.de"
ADMIN_PASSWORD = "admin-pw-1"


def connect_test_database(database_url: str) -> Iterator[Connection]:
    # Skipped, when the URL is not MariaDB or the container is not running.
    url = make_url(database_url)
    if url.get_backend_name() not in ("mysql", "mariadb"):
        pytest.skip("not a MariaDB URL")
    engine = make_engine(url.set(database=TEST_DATABASE))
    try:
        connection = engine.connect()
    except OperationalError:
        pytest.skip("MariaDB is not reachable: docker compose up -d")
    with connection:
        yield connection
    engine.dispose()


@pytest.fixture
def mariadb() -> Iterator[Connection]:
    """
    daas_app on daas_auth_test: the service's account, from .env.
    """
    yield from connect_test_database(load_settings().database_url)


@pytest.fixture
def mariadb_migrate() -> Iterator[Connection]:
    """
    daas_migrate on daas_auth_test: Alembic's account, from .env.migrate.
    """
    yield from connect_test_database(load_migration_settings().database_url)


# ---- API on SQLite ---------------------------------------------


@pytest.fixture(scope="session")
def head_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A SQLite file at head, migrated once per test run."""
    path = tmp_path_factory.mktemp("head") / "head.sqlite3"
    engine = make_engine(f"sqlite:///{path}")
    with engine.connect() as connection:
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.commit()
    engine.dispose()
    return path


@pytest.fixture
def app(head_database: Path, tmp_path: Path) -> Iterator[FastAPI]:
    """The service on a copy of head: every test starts with the same rows.

    A file, not sqlite:// in memory: the test client calls the routes from other
    threads, and every thread would get its own empty in-memory database.
    """
    path = tmp_path / "test.sqlite3"
    shutil.copy(head_database, path)
    app = create_app(Settings(database_url=f"sqlite:///{path}"))
    with Session(app.state.engine) as session:
        seed_database(session, email=ADMIN_EMAIL, name="Admin", password=ADMIN_PASSWORD)
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as client:
        yield client


@pytest.fixture
def add_user(app: FastAPI) -> Callable[..., int]:
    """add_user(email, password_hash, role="user", enabled=True) -> the new id."""

    def add(
        email: str, password_hash: str, role: str = "user", enabled: bool = True
    ) -> int:
        now = datetime(2026, 11, 1)
        with Session(app.state.engine) as session:
            user = User(
                guid=str(uuid4()),
                name=email.split("@")[0],
                email=email,
                password=password_hash,
                enabled=enabled,
                created_at=now,
                updated_at=now,
            )
            session.add(user)
            session.flush()
            role_id = session.scalars(select(Role.id).where(Role.name == role)).one()
            session.add(
                UserRole(
                    user_id=user.id, role_id=role_id, created_at=now, updated_at=now
                )
            )
            session.commit()
            return user.id

    return add
