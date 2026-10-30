from collections.abc import Iterator

import pytest
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

from daas_auth.config import load_settings
from daas_auth.db import make_engine


@pytest.fixture
def mariadb() -> Iterator[Connection]:
    # The container from compose.yaml, reached the way the service reaches it:
    # DAAS_AUTH_DATABASE_URL from .env. Skipped, with the reason in the
    # summary, when it is not a MariaDB URL or the container is not running.
    engine = make_engine(load_settings().database_url)
    if engine.dialect.name not in ("mysql", "mariadb"):
        pytest.skip("DAAS_AUTH_DATABASE_URL is not a MariaDB URL")
    try:
        connection = engine.connect()
    except OperationalError:
        pytest.skip("MariaDB is not reachable: docker compose up -d")
    with connection:
        yield connection
    engine.dispose()
