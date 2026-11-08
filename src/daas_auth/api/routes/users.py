"""
User-related endpoints for admin dashboard
"""

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import (
    Acting,
    BreachCheck,
    DbSession,
    Now,
    require_scope,
)
from daas_auth.api.schemas import (
    AdminPublic,
    Message,
    UserCreate,
    UserPublic,
    UserUpdate,
)
from daas_auth.domain import accounts
from daas_auth.domain.accounts import ADMINS
from daas_auth.models import User, UserToUserGroup

# In PHP every route here needs the admin scope (security: oauth2-user admin).
admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])
# The user dashboard's routes, and the registration page's: anyone may call it.
user_router = APIRouter(dependencies=[Depends(require_scope("user"))])
public_router = APIRouter()


@admin_router.get("/users")
def user_list(session: DbSession) -> list[UserPublic]:
    """
    Every account that is not an admin, disabled ones too, by id.
    """
    groups: defaultdict[int, list[int]] = defaultdict(list)
    links = select(UserToUserGroup.user_id, UserToUserGroup.user_group_id)
    for user_id, group_id in session.execute(
        links.order_by(UserToUserGroup.user_group_id)
    ):
        groups[user_id].append(group_id)
    users = session.scalars(
        select(User).where(User.id.not_in(ADMINS)).order_by(User.id)
    )
    return [UserPublic.of(user, groups[user.id]) for user in users]


@admin_router.get("/user/{user_id}")
def user_get(user_id: int, session: DbSession) -> AdminPublic | UserPublic:
    """
    One account. As in PHP, an admin's id gives the admin's shape.
    """
    account = accounts.find_account(session, user_id)
    if accounts.is_admin(session, user_id):
        return AdminPublic.model_validate(account)
    return UserPublic.of(account, accounts.group_ids(session, user_id))


@admin_router.post("/user")
def user_create(
    body: UserCreate,
    session: DbSession,
    actor: Acting,
    at: Now,
    check_breaches: BreachCheck,
) -> UserPublic:
    """
    The admin dashboard's Create an account. Admin only, unlike PHP; it starts disabled.
    """
    user = accounts.create_account(
        session,
        name=body.name,
        email=body.email,
        password=body.password,
        role="user",
        groups=body.groups,
        check_breaches=check_breaches,
        actor=actor,
        now=at,
    )
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user.id))


@admin_router.patch("/user/{user_id}")
def user_update(
    user_id: int,
    body: UserUpdate,
    session: DbSession,
    actor: Acting,
    at: Now,
    check_breaches: BreachCheck,
) -> Message:
    """
    PHP's answer: only a message, unlike enable and disable.
    """
    accounts.update_user(
        session,
        user_id,
        name=body.name,
        email=body.email,
        password=body.password,
        groups=body.groups,
        check_breaches=check_breaches,
        actor=actor,
        now=at,
    )
    session.commit()
    return Message(message="User updated")


@admin_router.post("/user/{user_id}/enable")
def user_enable(user_id: int, session: DbSession, actor: Acting, at: Now) -> UserPublic:
    user = accounts.set_enabled(session, user_id, True, actor=actor, now=at)
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user_id))


@admin_router.post("/user/{user_id}/disable")
def user_disable(
    user_id: int, session: DbSession, actor: Acting, at: Now
) -> UserPublic:
    user = accounts.set_enabled(session, user_id, False, actor=actor, now=at)
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user_id))


@admin_router.delete("/user/{user_id}")
def user_delete(user_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    accounts.delete_user(session, user_id, actor=actor, now=at)
    session.commit()
    return "User deleted"  # PHP's answer, a JSON string
