"""
Desktop groups: which desktops belong together, and which user groups may use them.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daas_auth.domain import links
from daas_auth.domain.activity import Action, Actor, log_change, stamp
from daas_auth.domain.errors import Refused, refuse_unknown
from daas_auth.domain.user_groups import find_user_group
from daas_auth.models import (
    Desktop,
    DesktopGroup,
    DesktopGroupUserGroup,
    DesktopToDesktopGroup,
    UserGroup,
)


def find_desktop_group(session: Session, group_id: int) -> DesktopGroup:
    group = session.get(DesktopGroup, group_id)
    if group is None:
        raise Refused(404, f"No desktop group has the id {group_id}.")
    return group


def known_desktop_groups(session: Session, ids: list[int]) -> list[int]:
    """The ids once each, or 400: a group that doesn't exist is never dropped."""
    wanted = sorted(set(ids))
    known = set(
        session.scalars(select(DesktopGroup.id).where(DesktopGroup.id.in_(wanted)))
    )
    refuse_unknown(wanted, known, "desktop group")
    return wanted


def desktop_ids(session: Session, group_id: int) -> list[int]:
    """The desktops in the group, by id."""
    return list(
        session.scalars(
            select(DesktopToDesktopGroup.desktop_id)
            .where(DesktopToDesktopGroup.desktop_group_id == group_id)
            .order_by(DesktopToDesktopGroup.desktop_id)
        )
    )


def create_desktop_group(
    session: Session,
    *,
    description: str,
    desktops: list[int],
    actor: Actor,
    now: datetime,
) -> DesktopGroup:
    """
    Desktops are stored: PHP dropped desktopIds.
    """
    desktops = _known_desktops(session, desktops)
    group = DesktopGroup(description=description, **stamp(actor, now))
    session.add(group)
    session.flush()  # the id is known from here on
    for desktop_id in desktops:
        session.add(
            DesktopToDesktopGroup(
                desktop_id=desktop_id, desktop_group_id=group.id, **stamp(actor, now)
            )
        )
    log_change(
        session, Action.DESKTOP_GROUP_CREATE, "desktop_groups", group.id, actor, now
    )
    return group


def delete_desktop_group(
    session: Session, group_id: int, *, actor: Actor, now: datetime
) -> None:
    """
    Its desktops and user groups lose the group; they themselves stay.
    """
    group = find_desktop_group(session, group_id)
    links.remove(
        session,
        DesktopToDesktopGroup,
        DesktopToDesktopGroup.desktop_group_id == group.id,
        actor=actor,
        now=now,
    )
    links.remove(
        session,
        DesktopGroupUserGroup,
        DesktopGroupUserGroup.desktop_group_id == group.id,
        actor=actor,
        now=now,
    )
    session.delete(group)
    log_change(
        session, Action.DESKTOP_GROUP_DELETE, "desktop_groups", group.id, actor, now
    )


def user_groups_of(session: Session, group_id: int) -> list[UserGroup]:
    """
    The user groups that may use the desktop group, by id.
    """
    return list(
        session.scalars(
            select(UserGroup)
            .join(
                DesktopGroupUserGroup,
                DesktopGroupUserGroup.user_group_id == UserGroup.id,
            )
            .where(DesktopGroupUserGroup.desktop_group_id == group_id)
            .order_by(UserGroup.id)
        )
    )


def desktop_groups_of(session: Session, user_group_id: int) -> list[DesktopGroup]:
    """The desktop groups the user group may use, by id."""
    return list(
        session.scalars(
            select(DesktopGroup)
            .join(
                DesktopGroupUserGroup,
                DesktopGroupUserGroup.desktop_group_id == DesktopGroup.id,
            )
            .where(DesktopGroupUserGroup.user_group_id == user_group_id)
            .order_by(DesktopGroup.id)
        )
    )


def add_user_group(
    session: Session, group_id: int, user_group_id: int, *, actor: Actor, now: datetime
) -> None:
    """From now on the members of the user group may use the group's desktops."""
    group = find_desktop_group(session, group_id)
    user_group = find_user_group(session, user_group_id)
    session.add(
        DesktopGroupUserGroup(
            desktop_group_id=group.id, user_group_id=user_group.id, **stamp(actor, now)
        )
    )
    try:
        session.flush()  # the primary key decides, even when two requests race
    except IntegrityError:
        raise Refused(
            409, f"User group {user_group_id} is in desktop group {group_id} already."
        ) from None
    log_link(session, group.id, f"user group {user_group.id} added", actor, now)


def remove_user_group(
    session: Session, group_id: int, user_group_id: int, *, actor: Actor, now: datetime
) -> None:
    """The very next access check of the members already says no (R-3)."""
    if session.get(DesktopGroupUserGroup, (group_id, user_group_id)) is None:
        raise Refused(404, "That user group is not in that desktop group.")
    links.remove(
        session,
        DesktopGroupUserGroup,
        DesktopGroupUserGroup.desktop_group_id == group_id,
        DesktopGroupUserGroup.user_group_id == user_group_id,
        actor=actor,
        now=now,
    )
    log_link(session, group_id, f"user group {user_group_id} removed", actor, now)


def log_link(
    session: Session, group_id: int, details: str, actor: Actor, now: datetime
) -> None:
    """A link of the group changed: one desktop_group_update row that says which."""
    log_change(
        session,
        Action.DESKTOP_GROUP_UPDATE,
        "desktop_groups",
        group_id,
        actor,
        now,
        details,
    )


def _known_desktops(session: Session, ids: list[int]) -> list[int]:
    wanted = sorted(set(ids))
    known = set(session.scalars(select(Desktop.id).where(Desktop.id.in_(wanted))))
    refuse_unknown(wanted, known, "desktop")
    return wanted
