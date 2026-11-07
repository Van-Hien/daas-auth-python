"""
Users' and admins' accounts.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daas_auth.domain import links
from daas_auth.domain.activity import (
    Action,
    Actor,
    RevokedReason,
    log_change,
    record,
    stamp,
)
from daas_auth.domain.emails import normalise_email
from daas_auth.domain.errors import Refused
from daas_auth.domain.passwords import hash_password
from daas_auth.domain.user_groups import known_user_groups
from daas_auth.models import (
    OAuth2Token,
    Role,
    User,
    UserRole,
    UserToUserGroup,
)

# New passwords: no rules on the kind of characters, only the length.
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128

# The ids of the accounts that hold the admin role.
ADMINS = select(UserRole.user_id).join(Role).where(Role.name == "admin")


def is_admin(session: Session, user_id: int) -> bool:
    return session.scalar(ADMINS.where(UserRole.user_id == user_id)) is not None


def find_account(session: Session, user_id: int) -> User:
    """
    A user or an admin.
    """
    account = session.get(User, user_id)
    if account is None:
        raise Refused(404, f"No account has the id {user_id}.")
    return account


def find_user(session: Session, user_id: int) -> User:
    """
    A user who is not an admin: admins have routes of their own.
    """
    user = session.get(User, user_id)
    if user is None:
        raise Refused(404, f"No user has the id {user_id}.")
    if is_admin(session, user_id):
        raise Refused(409, f"Account {user_id} is an admin: use /admin/{user_id}.")
    return user


def find_admin(session: Session, admin_id: int) -> User:
    admin = session.get(User, admin_id)
    if admin is None or not is_admin(session, admin_id):
        raise Refused(404, f"No admin has the id {admin_id}.")
    return admin


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
    groups = known_user_groups(session, groups)
    account = User(
        guid=str(uuid4()),
        name=name,
        email=normalise_email(email),
        password=hash_password(password),
        enabled=role == "admin",
        **stamp(actor, now),
    )
    session.add(account)
    try:
        session.flush()  # the INSERT runs now: the unique email decides, and id is known
    except IntegrityError:
        raise Refused(409, "An account with this email exists already.") from None
    role_id = session.scalars(select(Role.id).where(Role.name == role)).one()
    session.add(UserRole(user_id=account.id, role_id=role_id, **stamp(actor, now)))
    for group_id in groups:
        session.add(
            UserToUserGroup(
                user_id=account.id, user_group_id=group_id, **stamp(actor, now)
            )
        )
    action = Action.ADMIN_CREATE if role == "admin" else Action.USER_CREATE
    log_change(session, action, "users", account.id, actor, now)
    return account


def update_user(
    session: Session,
    user_id: int,
    *,
    name: str | None,
    email: str | None,
    password: str | None,
    groups: list[int] | None,
    actor: Actor,
    now: datetime,
) -> User:
    """
    Only the fields that were sent. A new password ends every session of the user.
    """
    user = find_user(session, user_id)
    if name is not None:
        user.name = name
    if email is not None:
        user.email = normalise_email(email)
    if password is not None:
        user.password = hash_password(password)
        _revoke_user_tokens(session, user.id, actor, now)
    if groups is not None:
        links.replace(
            session,
            UserToUserGroup,
            UserToUserGroup.user_id,
            user.id,
            UserToUserGroup.user_group_id,
            known_user_groups(session, groups),
            actor=actor,
            now=now,
        )
    user.updated_at, user.updated_by = now, actor.id
    try:
        session.flush()
    except IntegrityError:
        raise Refused(409, "An account with this email exists already.") from None
    log_change(session, Action.USER_UPDATE, "users", user.id, actor, now)
    return user


def set_enabled(
    session: Session, user_id: int, enabled: bool, *, actor: Actor, now: datetime
) -> User:
    """
    A disabled user is refused at once: the bearer check reads enabled on every request.
    """
    user = find_user(session, user_id)
    user.enabled = enabled
    user.updated_at, user.updated_by = now, actor.id
    action = Action.USER_ENABLE if enabled else Action.USER_DISABLE
    log_change(session, action, "users", user.id, actor, now)
    return user


def delete_user(session: Session, user_id: int, *, actor: Actor, now: datetime) -> None:
    _delete_account(
        session, find_user(session, user_id), Action.USER_DELETE, actor, now
    )


def delete_admin(
    session: Session, admin_id: int, *, actor: Actor, now: datetime
) -> None:
    """
    Never the last admin, and never yourself: without an admin nobody can manage
    accounts any more, and daas-auth seed refuses a database that isn't empty.
    """
    admin = find_admin(session, admin_id)
    if admin.id == actor.id:
        raise Refused(409, "An admin cannot delete their own account.")
    # FOR UPDATE: two admins deleting each other at once wait for each other.
    if len(session.scalars(ADMINS.with_for_update()).all()) <= 1:
        raise Refused(409, "The last admin cannot be deleted.")
    _delete_account(session, admin, Action.ADMIN_DELETE, actor, now)


def request_application(
    session: Session, application: str, language: str, *, actor: Actor, now: datetime
) -> None:
    """
    Recorded, not mailed: no mail leaves this service. PHP mailed it to the user.
    """
    record(
        session,
        Action.APPLICATION_REQUEST,
        ok=True,
        now=now,
        actor_id=actor.id,
        actor_email=actor.email,
        target_table="users",
        target_id=actor.id,
        source_ip=actor.source_ip,
        details=f"{application} ({language})"[:255],
    )


def _delete_account(
    session: Session, account: User, action: Action, actor: Actor, now: datetime
) -> None:
    """
    The rows that point at the account first: they have no ON DELETE, so MariaDB
    refuses the user while they exist. Its tokens go with it (ON DELETE CASCADE).
    """
    for link in (UserRole, UserToUserGroup):
        links.remove(session, link, link.user_id == account.id, actor=actor, now=now)
    session.delete(account)
    log_change(session, action, "users", account.id, actor, now)


def _revoke_user_tokens(
    session: Session, user_id: int, actor: Actor, now: datetime
) -> None:
    session.execute(
        update(OAuth2Token)
        .where(OAuth2Token.user_id == user_id, OAuth2Token.revoked_at.is_(None))
        .values(
            revoked_at=now,
            updated_at=now,
            updated_by=actor.id,
            revoked_reason=RevokedReason.PASSWORD_CHANGED,
        )
    )
