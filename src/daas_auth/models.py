"""
The tables as Python classes (SQLAlchemy ORM), matching migration head
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    text,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Every key, index and constraint gets a name built from these patterns, so a
# later migration can drop it by that name, on MariaDB and on SQLite alike.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

ID = BigInteger().with_variant(Integer(), "sqlite")
TIMESTAMP = DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql", "mariadb")
# PHP's table options (schema.sql), for every new table. SQLite ignores mysql_ options.
MYSQL: dict[str, Any] = {
    "mysql_engine": "InnoDB",
    "mysql_charset": "utf8mb4",
    "mysql_collate": "utf8mb4_bin",
    "mysql_row_format": "DYNAMIC",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Audited:
    """
    The four audit columns every table has. Times are UTC.

    On insert, updated_* get the same values as created_*.
    _by is a user id without a foreign key, NULL when nobody is logged in.
    """

    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, sort_order=100)
    created_by: Mapped[int | None] = mapped_column(BigInteger, sort_order=101)
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP, sort_order=102)
    updated_by: Mapped[int | None] = mapped_column(BigInteger, sort_order=103)


class User(Audited, Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("registration_idx", "email", "registration_code"),
        {
            # an id is never given out twice (h)
            "sqlite_autoincrement": True,
            **MYSQL,
        },
    )

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    guid: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    # should be stored normalised to ensure uniqueness
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password: Mapped[str] = mapped_column(String(255))  # a hash, never the password
    enabled: Mapped[bool] = mapped_column(Boolean(), server_default=text("0"))
    registration_code: Mapped[str | None] = mapped_column(String(8))
    registration_code_timeout: Mapped[datetime | None] = mapped_column(DateTime)
    registration_used_moment: Mapped[datetime | None] = mapped_column(DateTime)


class UserGroup(Audited, Base):
    __tablename__ = "user_groups"
    __table_args__ = MYSQL

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class UserToUserGroup(Audited, Base):
    __tablename__ = "users_to_user_groups"
    __table_args__ = MYSQL

    user_id: Mapped[int] = mapped_column(
        ID, ForeignKey("users.id"), primary_key=True, index=True
    )
    user_group_id: Mapped[int] = mapped_column(
        ID, ForeignKey("user_groups.id"), primary_key=True, index=True
    )


class Desktop(Audited, Base):
    __tablename__ = "desktops"
    __table_args__ = MYSQL

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class DesktopGroup(Audited, Base):
    __tablename__ = "desktop_groups"
    __table_args__ = MYSQL

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class DesktopToDesktopGroup(Audited, Base):
    __tablename__ = "desktops_to_desktop_groups"
    __table_args__ = MYSQL

    desktop_id: Mapped[int] = mapped_column(
        ID, ForeignKey("desktops.id"), primary_key=True, index=True
    )
    desktop_group_id: Mapped[int] = mapped_column(
        ID, ForeignKey("desktop_groups.id"), primary_key=True, index=True
    )


class DesktopGroupUserGroup(Audited, Base):
    __tablename__ = "desktopgroup_usergroup"
    __table_args__ = MYSQL

    desktopgroup_id: Mapped[int] = mapped_column(
        ID,
        ForeignKey("desktop_groups.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    usergroup_id: Mapped[int] = mapped_column(
        ID,
        ForeignKey("user_groups.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )


class OAuth2Client(Audited, Base):
    __tablename__ = "oauth2_clients"
    __table_args__ = MYSQL

    identifier: Mapped[str] = mapped_column(String(200), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    name: Mapped[str] = mapped_column(String(200))
    redirect_uris: Mapped[str] = mapped_column(
        Text().with_variant(mysql.LONGTEXT(), "mysql", "mariadb")
    )  # JSON text, as in PHP
    is_confidential: Mapped[bool] = mapped_column(Boolean)
    # SHA-256 of the secret as hex (0009). NULL: a public client, such as test-client.
    secret_hash: Mapped[str | None] = mapped_column(String(64))


class Role(Audited, Base):
    __tablename__ = "roles"
    __table_args__ = MYSQL

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    name: Mapped[str] = mapped_column(String(16), unique=True)


class UserRole(Audited, Base):
    """
    System-versioned on MariaDB (0003): every old version of a row is kept.
    """

    __tablename__ = "user_roles"
    __table_args__ = MYSQL

    user_id: Mapped[int] = mapped_column(ID, ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[int] = mapped_column(
        ID, ForeignKey("roles.id"), primary_key=True, index=True
    )


class OAuth2Token(Audited, Base):
    """
    One issued access/refresh pair. Only SHA-256 hashes.
    """

    __tablename__ = "oauth2_tokens"
    __table_args__ = MYSQL

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    family_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(
        ID, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    client_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("oauth2_clients.identifier"), index=True
    )
    scopes: Mapped[str] = mapped_column(String(255))
    access_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    access_expires_at: Mapped[datetime] = mapped_column(TIMESTAMP)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    refresh_expires_at: Mapped[datetime] = mapped_column(TIMESTAMP)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)


class ActivityLog(Audited, Base):
    """
    Append-only: the service only gonna inserts here.
    """

    __tablename__ = "activity_log"
    __table_args__ = (
        Index("ix_activity_log_target_table", "target_table", "target_id"),
        Index("ix_activity_log_actor_email", "actor_email", "created_at"),
        MYSQL,
    )

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    action: Mapped[str] = mapped_column(String(32))
    result: Mapped[str] = mapped_column(String(8))
    reason: Mapped[str | None] = mapped_column(String(32))
    actor_email: Mapped[str | None] = mapped_column(String(255))
    target_table: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[int | None] = mapped_column(BigInteger)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[str | None] = mapped_column(String(255))
