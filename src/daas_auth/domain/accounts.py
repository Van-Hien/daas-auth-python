"""
Users and admins accounts.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daas_auth.domain.activity import Action, record
from daas_auth.domain.emails import normalise_email
from daas_auth.domain.errors import Refused
from daas_auth.domain.passwords import hash_password
from daas_auth.models import Role, User, UserGroup, UserRole, UserToUserGroup

# New passwords: no rules on the kind of characters, only the length.
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128

# The ids of the accounts that hold the admin role.
ADMINS = select(UserRole.user_id).join(Role).where(Role.name == "admin")


@dataclass(frozen=True)
class Actor:
    """
    The actor (probably admin) who makes a change: for the _by columns and activity_log.
    """

    id: int
    email: str
    source_ip: str | None


def is_admin(session: Session, user_id: int) -> bool:
    return session.scalar(ADMINS.where(UserRole.user_id == user_id)) is not None


def find_account(session: Session, user_id: int) -> User:
    """A user or an admin."""
    account = session.get(User, user_id)
    if account is None:
        raise Refused(404, f"No account has the id {user_id}.")
    return account


def group_ids(session: Session, user_id: int) -> list[int]:
    return list(
        session.scalars(
            select(UserToUserGroup.user_group_id)
            .where(UserToUserGroup.user_id == user_id)
            .order_by(UserToUserGroup.user_group_id)
        )
    )


def create_account(
    session: Session,
    *,
    name: str,
    email: str,
    password: str,
    role: str,
    groups: list[int],
    actor: Actor,
    now: datetime,
) -> User:
    """
    A user starts disabled and waits for an admin; an admin starts enabled, as in PHP.
    """
    groups = _known_groups(session, groups)
    account = User(
        guid=str(uuid4()),
        name=name,
        email=normalise_email(email),
        password=hash_password(password),
        enabled=role == "admin",
        **_stamp(actor, now),
    )
    session.add(account)
    try:
        session.flush()  # the INSERT runs now: the unique email decides, and id is known
    except IntegrityError:
        raise Refused(409, "An account with this email exists already.") from None
    role_id = session.scalars(select(Role.id).where(Role.name == role)).one()
    session.add(UserRole(user_id=account.id, role_id=role_id, **_stamp(actor, now)))
    for group_id in groups:
        session.add(
            UserToUserGroup(
                user_id=account.id, user_group_id=group_id, **_stamp(actor, now)
            )
        )
    _log(session, Action.USER_CREATE, account.id, actor, now)
    return account


def _known_groups(session: Session, groups: list[int]) -> list[int]:
    """The ids once each, or 400: a group that doesn't exist is never dropped."""
    wanted = sorted(set(groups))
    known = set(session.scalars(select(UserGroup.id).where(UserGroup.id.in_(wanted))))
    unknown = [group_id for group_id in wanted if group_id not in known]
    if unknown:
        listed = ", ".join(str(group_id) for group_id in unknown)
        raise Refused(400, f"No user group has the id {listed}.")
    return wanted


def _stamp(actor: Actor, now: datetime) -> dict[str, Any]:
    # On insert, updated_* get the same values as created_*.
    return {
        "created_at": now,
        "created_by": actor.id,
        "updated_at": now,
        "updated_by": actor.id,
    }


def _log(
    session: Session, action: Action, target_id: int, actor: Actor, now: datetime
) -> None:
    record(
        session,
        action,
        ok=True,
        now=now,
        actor_id=actor.id,
        actor_email=actor.email,
        target_table="users",
        target_id=target_id,
        source_ip=actor.source_ip,
    )
