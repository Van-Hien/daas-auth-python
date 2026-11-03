"""
User groups: the admin dashboard's groups of users. Desktop groups are given to them.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain import links
from daas_auth.domain.activity import Action, Actor, log_change, stamp
from daas_auth.domain.errors import Refused
from daas_auth.models import (
    DesktopGroupUserGroup,
    Role,
    User,
    UserGroup,
    UserRole,
    UserToUserGroup,
)


def find_user_group(session: Session, group_id: int) -> UserGroup:
    group = session.get(UserGroup, group_id)
    if group is None:
        raise Refused(404, f"No user group has the id {group_id}.")
    return group


def known_user_groups(session: Session, ids: list[int]) -> list[int]:
    """The ids once each, or 400: a group that doesn't exist is never dropped."""
    wanted = sorted(set(ids))
    known = set(session.scalars(select(UserGroup.id).where(UserGroup.id.in_(wanted))))
    _refuse_unknown(wanted, known, "user group")
    return wanted


def create_user_group(
    session: Session, *, description: str, actor: Actor, now: datetime
) -> UserGroup:
    group = UserGroup(description=description, **stamp(actor, now))
    session.add(group)
    session.flush()  # the id is known from here on
    log_change(session, Action.USER_GROUP_CREATE, "user_groups", group.id, actor, now)
    return group


def update_user_group(
    session: Session,
    group_id: int,
    *,
    description: str | None,
    user_ids: list[int] | None,
    actor: Actor,
    now: datetime,
) -> UserGroup:
    """
    Only the fields that were sent. user_ids replaces the members, as in PHP.
    """
    group = find_user_group(session, group_id)
    if description is not None:
        group.description = description
    if user_ids is not None:
        links.replace(
            session,
            UserToUserGroup,
            UserToUserGroup.user_group_id,
            group.id,
            UserToUserGroup.user_id,
            _known_users(session, user_ids),
            actor=actor,
            now=now,
        )
    group.updated_at, group.updated_by = now, actor.id
    log_change(session, Action.USER_GROUP_UPDATE, "user_groups", group.id, actor, now)
    return group


def delete_user_group(
    session: Session, group_id: int, *, actor: Actor, now: datetime
) -> None:
    """
    Its members and its desktop groups lose the group; the users and desktop
    groups themselves stay.
    """
    group = find_user_group(session, group_id)
    links.remove(
        session,
        UserToUserGroup,
        UserToUserGroup.user_group_id == group.id,
        actor=actor,
        now=now,
    )
    links.remove(
        session,
        DesktopGroupUserGroup,
        DesktopGroupUserGroup.user_group_id == group.id,
        actor=actor,
        now=now,
    )
    session.delete(group)
    log_change(session, Action.USER_GROUP_DELETE, "user_groups", group.id, actor, now)


def _known_users(session: Session, ids: list[int]) -> list[int]:
    """Users only: an admin has no groups, as in PHP."""
    wanted = sorted(set(ids))
    known = set(
        session.scalars(
            select(User.id)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role)
            .where(User.id.in_(wanted), Role.name == "user")
        )
    )
    _refuse_unknown(wanted, known, "user")
    return wanted


def _refuse_unknown(wanted: list[int], known: set[int], what: str) -> None:
    unknown = [one for one in wanted if one not in known]
    if unknown:
        listed = ", ".join(str(one) for one in unknown)
        raise Refused(400, f"No {what} has the id {listed}.")
