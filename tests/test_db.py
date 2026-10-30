import pytest
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from daas_auth.db import check_strict_mode, make_engine


def test_sqlite_is_not_checked() -> None:
    with make_engine("sqlite://").connect() as connection:
        check_strict_mode(connection)


@pytest.mark.mariadb
def test_container_session_is_strict(mariadb: Connection) -> None:
    check_strict_mode(mariadb)


@pytest.mark.mariadb
def test_non_strict_session_is_refused(mariadb: Connection) -> None:
    mariadb.exec_driver_sql("SET SESSION sql_mode = ''")
    with pytest.raises(RuntimeError, match="not strict"):
        check_strict_mode(mariadb)


@pytest.mark.mariadb
def test_app_account_cannot_create_tables(mariadb: Connection) -> None:
    with pytest.raises(SQLAlchemyError, match="1142"):
        mariadb.exec_driver_sql("CREATE TABLE t (id int)")
