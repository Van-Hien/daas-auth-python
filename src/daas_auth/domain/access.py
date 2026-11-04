"""
Which desktops a user may use: a user may use a desktop if one of the user's groups
is linked to one of the desktop's groups. Admins may use every desktop.

Read on every request that asks, never cached: a link removed now counts at once.
"""

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from daas_auth.domain.accounts import is_admin
from daas_auth.domain.errors import Refused
from daas_auth.models import (
    Desktop,
    DesktopGroupUserGroup,
    DesktopToDesktopGroup,
    UserToUserGroup,
)


def _allowed(user_id: int) -> Select[Desktop]:
    # user -> user groups -> desktop groups -> desktops; ids only ever compared
    # within one table, unlike PHP's hasAccessToDesktop.
    return (
        select(Desktop)
        .join(DesktopToDesktopGroup, DesktopToDesktopGroup.desktop_id == Desktop.id)
        .join(
            DesktopGroupUserGroup,
            DesktopGroupUserGroup.desktop_group_id
            == DesktopToDesktopGroup.desktop_group_id,
        )
        .join(
            UserToUserGroup,
            UserToUserGroup.user_group_id == DesktopGroupUserGroup.user_group_id,
        )
        .where(UserToUserGroup.user_id == user_id)
        .distinct()
    )


def allowed_desktops(session: Session, user_id: int) -> list[Desktop]:
    """For display only: the per-action check is check_desktop."""
    query = select(Desktop) if is_admin(session, user_id) else _allowed(user_id)
    return list(session.scalars(query.order_by(Desktop.id)))


def check_desktop(session: Session, user_id: int, quart_object_id: str) -> Desktop:
    """
    The desktop that is this Quart object, if the user may use it. 404 when no
    desktop is that object, 403 when the user may not.
    """
    desktop = session.scalars(
        select(Desktop).where(Desktop.quart_object_id == quart_object_id)
    ).one_or_none()
    if desktop is None:
        raise Refused(404, f"No desktop is Quart object {quart_object_id}.")
    if is_admin(session, user_id):
        return desktop
    allowed = session.scalars(
        _allowed(user_id).where(Desktop.id == desktop.id).limit(1)
    ).first()
    if allowed is None:
        raise Refused(403, f"You may not use desktop {desktop.id}.")
    return desktop
