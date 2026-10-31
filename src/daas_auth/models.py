"""
The tables as Python classes (SQLAlchemy ORM), matching migration head
"""

from datetime import datetime

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
        Index("guid_idx", "guid"),
        Index("registration_idx", "email", "registration_code"),
        {"sqlite_autoincrement": True},  # an id is never given out twice (h)
    )

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    guid: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255))
    password: Mapped[str] = mapped_column(String(255))  # a hash, never the password
    enabled: Mapped[bool] = mapped_column(Boolean(), server_default=text("0"))
    role: Mapped[str] = mapped_column(String(16))
    registration_code: Mapped[str | None] = mapped_column(String(8))
    registration_code_timeout: Mapped[datetime | None] = mapped_column(DateTime)
    registration_used_moment: Mapped[datetime | None] = mapped_column(DateTime)


class UserGroup(Audited, Base):
    __tablename__ = "user_groups"

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class UserToUserGroup(Audited, Base):
    __tablename__ = "users_to_user_groups"

    user_id: Mapped[int] = mapped_column(
        ID, ForeignKey("users.id"), primary_key=True, index=True
    )
    user_group_id: Mapped[int] = mapped_column(
        ID, ForeignKey("user_groups.id"), primary_key=True, index=True
    )


class Desktop(Audited, Base):
    __tablename__ = "desktops"

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class DesktopGroup(Audited, Base):
    __tablename__ = "desktop_groups"

    id: Mapped[int] = mapped_column(ID, primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class DesktopToDesktopGroup(Audited, Base):
    __tablename__ = "desktops_to_desktop_groups"

    desktop_id: Mapped[int] = mapped_column(
        ID, ForeignKey("desktops.id"), primary_key=True, index=True
    )
    desktop_group_id: Mapped[int] = mapped_column(
        ID, ForeignKey("desktop_groups.id"), primary_key=True, index=True
    )


class DesktopGroupUserGroup(Audited, Base):
    __tablename__ = "desktopgroup_usergroup"

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

    identifier: Mapped[str] = mapped_column(String(200), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    name: Mapped[str] = mapped_column(String(200))
    redirect_uris: Mapped[str] = mapped_column(
        Text().with_variant(mysql.LONGTEXT(), "mysql", "mariadb")
    )  # JSON text, as in PHP
    is_confidential: Mapped[bool] = mapped_column(Boolean)
    secret: Mapped[str | None] = mapped_column(String(200))
