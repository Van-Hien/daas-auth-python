"""
Rows that link two other rows: user_roles and the three group link tables.

On MariaDB they keep every old version, so a removed row is stamped first: its last
version then says who removed it.
"""

from datetime import datetime

from sqlalchemy import ColumnElement, delete, select, update
from sqlalchemy.orm import InstrumentedAttribute, Session

from daas_auth.domain.activity import Actor, stamp
from daas_auth.models import (
    DesktopGroupUserGroup,
    DesktopToDesktopGroup,
    UserRole,
    UserToUserGroup,
)

Link = (
    type[UserRole]
    | type[UserToUserGroup]
    | type[DesktopToDesktopGroup]
    | type[DesktopGroupUserGroup]
)


def remove(
    session: Session,
    table: Link,
    *where: ColumnElement[bool],
    actor: Actor,
    now: datetime,
) -> None:
    session.execute(
        update(table).where(*where).values(updated_at=now, updated_by=actor.id)
    )
    session.execute(delete(table).where(*where))


def replace(
    session: Session,
    table: Link,
    owner: InstrumentedAttribute[int],
    owner_id: int,
    other: InstrumentedAttribute[int],
    wanted: list[int],
    *,
    actor: Actor,
    now: datetime,
) -> None:
    """
    Owner ends up linked to exactly the wanted ids; rows that stay are not touched.
    """
    mine = owner == owner_id
    remove(session, table, mine, other.not_in(wanted), actor=actor, now=now)
    kept = set(session.scalars(select(other).where(mine)))
    for other_id in wanted:
        if other_id not in kept:
            session.add(
                table(**{owner.key: owner_id, other.key: other_id}, **stamp(actor, now))
            )
