"""
Desktop groups: which desktops belong together, and which user groups may use them.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain import links
from daas_auth.domain.activity import Action, Actor, log_change, stamp
from daas_auth.domain.errors import Refused, refuse_unknown
from daas_auth.models import (
    Desktop,
    DesktopGroup,
    DesktopGroupUserGroup,
    DesktopToDesktopGroup,
)


def find_desktop_group(session: Session, group_id: int) -> DesktopGroup:
    group = session.get(DesktopGroup, group_id)
    if group is None:
        raise Refused(404, f"No desktop group has the id {group_id}.")
    return group


def known_desktop_groups(session: Session, ids: list[int]) -> list[int]:
    """
    The ids once each, or 422: a group that doesn't exist is never dropped.
    """
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
    """desktops are stored: PHP dropped desktopIds (R-3)."""
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


def _known_desktops(session: Session, ids: list[int]) -> list[int]:
    wanted = sorted(set(ids))
    known = set(session.scalars(select(Desktop.id).where(Desktop.id.in_(wanted))))
    refuse_unknown(wanted, known, "desktop")
    return wanted
