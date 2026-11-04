"""
Desktops: what a user may open. quart_object_id says which of Quart's objects it is.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daas_auth.domain import links
from daas_auth.domain.activity import Action, Actor, log_change, stamp
from daas_auth.domain.desktop_groups import (
    find_desktop_group,
    known_desktop_groups,
    log_link,
)
from daas_auth.domain.errors import Refused
from daas_auth.models import Desktop, DesktopToDesktopGroup


def find_desktop(session: Session, desktop_id: int) -> Desktop:
    desktop = session.get(Desktop, desktop_id)
    if desktop is None:
        raise Refused(404, f"No desktop has the id {desktop_id}.")
    return desktop


def group_ids(session: Session, desktop_id: int) -> list[int]:
    """The desktop groups the desktop is in, by id."""
    return list(
        session.scalars(
            select(DesktopToDesktopGroup.desktop_group_id)
            .where(DesktopToDesktopGroup.desktop_id == desktop_id)
            .order_by(DesktopToDesktopGroup.desktop_group_id)
        )
    )


def create_desktop(
    session: Session,
    *,
    description: str,
    name: str | None,
    quart_object_id: str | None,
    groups: list[int],
    actor: Actor,
    now: datetime,
) -> Desktop:
    """groups are desktop-group ids, and are stored: PHP dropped them (R-3)."""
    groups = known_desktop_groups(session, groups)
    desktop = Desktop(
        description=description,
        name=name,
        quart_object_id=quart_object_id,
        **stamp(actor, now),
    )
    session.add(desktop)
    _flush(session, quart_object_id)
    _set_groups(session, desktop.id, groups, actor, now)
    log_change(session, Action.DESKTOP_CREATE, "desktops", desktop.id, actor, now)
    return desktop


def update_desktop(
    session: Session,
    desktop_id: int,
    *,
    description: str | None,
    name: str | None,
    quart_object_id: str | None,
    groups: list[int] | None,
    actor: Actor,
    now: datetime,
) -> Desktop:
    """
    Only the fields that were sent. groups replaces the desktop groups.
    """
    desktop = find_desktop(session, desktop_id)
    if description is not None:
        desktop.description = description
    if name is not None:
        desktop.name = name
    if quart_object_id is not None:
        desktop.quart_object_id = quart_object_id
    if groups is not None:
        _set_groups(
            session, desktop.id, known_desktop_groups(session, groups), actor, now
        )
    desktop.updated_at, desktop.updated_by = now, actor.id
    _flush(session, quart_object_id)
    log_change(session, Action.DESKTOP_UPDATE, "desktops", desktop.id, actor, now)
    return desktop


def delete_desktop(
    session: Session, desktop_id: int, *, actor: Actor, now: datetime
) -> None:
    desktop = find_desktop(session, desktop_id)
    links.remove(
        session,
        DesktopToDesktopGroup,
        DesktopToDesktopGroup.desktop_id == desktop.id,
        actor=actor,
        now=now,
    )
    session.delete(desktop)
    log_change(session, Action.DESKTOP_DELETE, "desktops", desktop.id, actor, now)


def add_to_group(
    session: Session, desktop_id: int, group_id: int, *, actor: Actor, now: datetime
) -> None:
    desktop = find_desktop(session, desktop_id)
    group = find_desktop_group(session, group_id)
    session.add(
        DesktopToDesktopGroup(
            desktop_id=desktop.id, desktop_group_id=group.id, **stamp(actor, now)
        )
    )
    try:
        session.flush()  # the primary key decides, even when two requests race
    except IntegrityError:
        raise Refused(
            409, f"Desktop {desktop_id} is in desktop group {group_id} already."
        ) from None
    log_link(session, group.id, f"desktop {desktop.id} added", actor, now)


def remove_from_group(
    session: Session, desktop_id: int, group_id: int, *, actor: Actor, now: datetime
) -> None:
    if session.get(DesktopToDesktopGroup, (desktop_id, group_id)) is None:
        raise Refused(404, "That desktop is not in that desktop group.")
    links.remove(
        session,
        DesktopToDesktopGroup,
        DesktopToDesktopGroup.desktop_id == desktop_id,
        DesktopToDesktopGroup.desktop_group_id == group_id,
        actor=actor,
        now=now,
    )
    log_link(session, group_id, f"desktop {desktop_id} removed", actor, now)


def _set_groups(
    session: Session, desktop_id: int, groups: list[int], actor: Actor, now: datetime
) -> None:
    links.replace(
        session,
        DesktopToDesktopGroup,
        DesktopToDesktopGroup.desktop_id,
        desktop_id,
        DesktopToDesktopGroup.desktop_group_id,
        groups,
        actor=actor,
        now=now,
    )


def _flush(session: Session, quart_object_id: str | None) -> None:
    try:
        session.flush()  # the unique quart_object_id decides, even when two requests race
    except IntegrityError:
        raise Refused(
            409, f"Quart object {quart_object_id} is another desktop already."
        ) from None
