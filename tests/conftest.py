from collections.abc import Iterator

import pytest
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import OperationalError

from daas_auth.config import load_migration_settings, load_settings
from daas_auth.db import make_engine

# Tests use their own database, never daas_auth, so they can't touch real rows.
TEST_DATABASE = "daas_auth_test"


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
