import hashlib
from collections.abc import Iterator
from datetime import datetime

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from daas_auth.db import make_engine
from daas_auth.domain.accounts import create_account, delete_user, update_user
from daas_auth.domain.activity import Actor
from daas_auth.models import Role, User, UserGroup, UserRole


def alembic_config(connection: Connection) -> Config:
    config = Config("alembic.ini")
    config.attributes["connection"] = (
        connection  # env.py uses it instead of .env.migrate
    )
    return config


@pytest.fixture
def sqlite() -> Iterator[Connection]:
    engine = make_engine("sqlite://")
    with engine.connect() as connection:
        yield connection
    engine.dispose()  # the pool keeps an in-memory database open until this


def round_trip(connection: Connection) -> None:
    config = alembic_config(connection)
    command.upgrade(config, "head")
    command.check(config)  # the models match the migrations
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    command.downgrade(config, "base")  # leave the database empty again
    connection.commit()


def test_round_trip_on_sqlite(sqlite: Connection) -> None:
    round_trip(sqlite)


@pytest.mark.mariadb
def test_round_trip_on_mariadb(mariadb_migrate: Connection) -> None:
    round_trip(mariadb_migrate)


def test_php_rows_survive_the_migrations(sqlite: Connection) -> None:
    config = alembic_config(sqlite)
    command.upgrade(config, "0001")
    php_users = sa.table(
        "users",
        *(sa.column(name) for name in ("id", "guid", "name", "email", "password")),
        sa.column("enabled"),
        sa.column("role"),
    )
    sqlite.execute(
        php_users.insert(),
        [
            {
                "id": 1,
                "guid": "g1",
                "name": "A",
                "email": " Admin@X.de",
                "password": "h",
                "enabled": True,
                "role": "admin",
            },
            {
                "id": 2,
                "guid": "g2",
                "name": "U",
                "email": "user@x.de",
                "password": "h",
                "enabled": True,
                "role": "user",
            },
        ],
    )
    command.upgrade(config, "head")
    user_roles = sa.table("user_roles", sa.column("user_id"), sa.column("role_id"))
    rows = sqlite.execute(sa.select(user_roles).order_by(user_roles.c.user_id))
    assert rows.all() == [(1, 1), (2, 2)]  # roles: 1 admin, 2 user
    emails = sqlite.execute(
        sa.select(sa.column("email", sa.String)).select_from(sa.table("users"))
    )
    assert sorted(emails.scalars()) == ["admin@x.de", "user@x.de"]

    command.downgrade(config, "0003")  # 0004 back: users.role filled from user_roles
    roles = sqlite.execute(sa.select(php_users.c.id, php_users.c.role).order_by("id"))
    assert roles.all() == [(1, "admin"), (2, "user")]


def test_0009_keeps_only_a_hash_of_a_client_secret(sqlite: Connection) -> None:
    config = alembic_config(sqlite)
    command.upgrade(config, "0008")
    now = datetime(2026, 11, 2)
    clients = sa.table(
        "oauth2_clients",
        *(sa.column(name) for name in ("identifier", "version", "name")),
        *(sa.column(name) for name in ("redirect_uris", "is_confidential", "secret")),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    sqlite.execute(
        clients.insert(),
        [
            {
                "identifier": identifier,
                "version": 1,
                "name": identifier,
                "redirect_uris": "[]",
                "is_confidential": secret is not None,
                "secret": secret,
                "created_at": now,
                "updated_at": now,
            }
            for identifier, secret in (("public", None), ("quart", "s3cret"))
        ],
    )
    command.upgrade(config, "0009")
    hashes = sa.select(
        sa.column("identifier", sa.String), sa.column("secret_hash", sa.String)
    )
    rows = sqlite.execute(
        hashes.select_from(sa.table("oauth2_clients")).order_by("identifier")
    )
    assert rows.all() == [
        ("public", None),
        ("quart", hashlib.sha256(b"s3cret").hexdigest()),
    ]
    with pytest.raises(RuntimeError, match="can't be restored"):
        command.downgrade(config, "0008")


def test_two_spellings_of_one_email_stop_0005(sqlite: Connection) -> None:
    config = alembic_config(sqlite)
    command.upgrade(config, "0004")
    now = datetime(2026, 10, 30)
    users = sa.table(
        "users",
        *(sa.column(name) for name in ("guid", "name", "email", "password")),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    sqlite.execute(
        users.insert(),
        [
            {
                "guid": "g1",
                "name": "a",
                "email": "anna@x.de",
                "password": "h",
                "created_at": now,
                "updated_at": now,
            },
            {
                "guid": "g2",
                "name": "b",
                "email": "Anna@x.de",
                "password": "h",
                "created_at": now,
                "updated_at": now,
            },
        ],
    )
    with pytest.raises(RuntimeError, match="same email"):
        command.upgrade(config, "0005")


def test_0010_a_quart_object_is_at_most_one_desktop(sqlite: Connection) -> None:
    command.upgrade(alembic_config(sqlite), "0010")
    desktops = sa.table(
        "desktops",
        sa.column("description"),
        sa.column("quart_object_id"),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    now = datetime(2026, 11, 3)
    row = {"description": "d", "created_at": now, "updated_at": now}
    # Not linked yet: any number of desktops.
    sqlite.execute(desktops.insert(), [row | {"quart_object_id": None}] * 2)
    sqlite.execute(desktops.insert(), row | {"quart_object_id": "templateWin10"})
    with pytest.raises(IntegrityError):
        sqlite.execute(desktops.insert(), row | {"quart_object_id": "templateWin10"})


def test_0011_keeps_the_desktop_group_links(sqlite: Connection) -> None:
    config = alembic_config(sqlite)
    command.upgrade(config, "0010")
    now = datetime(2026, 11, 3)
    stamp = {"created_at": now, "updated_at": now}
    for name in ("desktop_groups", "user_groups"):
        groups = sa.table(
            name,
            sa.column("id"),
            sa.column("description"),
            sa.column("created_at", sa.DateTime()),
            sa.column("updated_at", sa.DateTime()),
        )
        sqlite.execute(groups.insert(), {"id": 7, "description": "g"} | stamp)
    links = sa.table(
        "desktopgroup_usergroup",
        sa.column("desktopgroup_id"),
        sa.column("usergroup_id"),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    sqlite.execute(links.insert(), {"desktopgroup_id": 7, "usergroup_id": 7} | stamp)
    command.upgrade(config, "0011")
    renamed = "SELECT desktop_group_id, user_group_id FROM desktopgroup_usergroup"
    assert sqlite.exec_driver_sql(renamed).all() == [(7, 7)]
    command.downgrade(config, "0010")
    old = "SELECT desktopgroup_id, usergroup_id FROM desktopgroup_usergroup"
    assert sqlite.exec_driver_sql(old).all() == [(7, 7)]


@pytest.fixture
def migrated(mariadb_migrate: Connection) -> Iterator[None]:
    """daas_auth_test at head for one test, emptied again afterwards."""
    config = alembic_config(mariadb_migrate)
    command.upgrade(config, "head")
    mariadb_migrate.commit()
    yield
    command.downgrade(config, "base")
    mariadb_migrate.commit()


@pytest.mark.mariadb
def test_user_roles_keeps_history_and_app_cannot_delete_it(
    migrated: None, mariadb: Connection
) -> None:
    now = datetime(2026, 10, 30)
    users = sa.table(
        "users",
        *(sa.column(name) for name in ("id", "guid", "name", "email", "password")),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    user_roles = sa.table(
        "user_roles",
        sa.column("user_id"),
        sa.column("role_id"),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    mariadb.execute(
        users.insert(),
        {
            "id": 1,
            "guid": "g1",
            "name": "a",
            "email": "a@x.de",
            "password": "h",
            "created_at": now,
            "updated_at": now,
        },
    )
    mariadb.execute(
        user_roles.insert().values(user_id=1, role_id=1, created_at=now, updated_at=now)
    )
    mariadb.commit()
    mariadb.execute(user_roles.delete())  # the admin role taken away again
    mariadb.commit()

    # FOR SYSTEM_TIME has no SQLAlchemy form: a fixed SQL text, MariaDB only (N-2).
    history = "SELECT COUNT(*) FROM user_roles FOR SYSTEM_TIME ALL"
    assert mariadb.exec_driver_sql(history).scalar_one() == 1
    with pytest.raises(SQLAlchemyError, match="1142"):  # DELETE HISTORY denied
        mariadb.exec_driver_sql("DELETE HISTORY FROM user_roles")
    mariadb.rollback()


@pytest.mark.mariadb
def test_deleting_a_user_on_mariadb(migrated: None, mariadb: Connection) -> None:
    now = datetime(2026, 11, 3)
    with Session(bind=mariadb) as session:
        user = User(
            guid="g1",
            name="a",
            email="a@x.de",
            password="h",
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.flush()
        role_id = session.scalars(sa.select(Role.id).where(Role.name == "user")).one()
        session.add(
            UserRole(user_id=user.id, role_id=role_id, created_at=now, updated_at=now)
        )
        session.commit()
        user_id = user.id

        # What a plain DELETE gets while user_roles still points at the user.
        with pytest.raises(SQLAlchemyError, match="1451"):
            session.execute(sa.delete(User))
        session.rollback()

        delete_user(session, user_id, actor=Actor(99, "admin@x.de", None), now=now)
        session.commit()
        assert session.get(User, user_id) is None

    # FOR SYSTEM_TIME has no SQLAlchemy form: a fixed SQL text, MariaDB only (N-2).
    history = "SELECT updated_by FROM user_roles FOR SYSTEM_TIME ALL ORDER BY row_end"
    assert mariadb.exec_driver_sql(history).scalars().all() == [None, 99]


@pytest.mark.mariadb
def test_group_links_keep_who_removed_them(migrated: None, mariadb: Connection) -> None:
    now = datetime(2026, 11, 3)
    with Session(bind=mariadb) as session:
        session.add(UserGroup(id=7, description="g", created_at=now, updated_at=now))
        session.flush()
        user = create_account(
            session,
            name="a",
            email="a@x.de",
            password="a-long-enough-pw",
            role="user",
            groups=[7],
            actor=Actor(99, "admin@x.de", None),
            now=now,
        )
        session.commit()
        update_user(
            session,
            user.id,
            name=None,
            email=None,
            password=None,
            groups=[],
            actor=Actor(98, "other@x.de", None),
            now=now,
        )
        session.commit()

    # FOR SYSTEM_TIME has no SQLAlchemy form: a fixed SQL text, MariaDB only (N-2).
    history = (
        "SELECT updated_by FROM users_to_user_groups FOR SYSTEM_TIME ALL"
        " ORDER BY row_end"
    )
    assert mariadb.exec_driver_sql(history).scalars().all() == [99, 98]
