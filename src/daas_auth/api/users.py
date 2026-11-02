"""
User-related endpoints for admin dashboard
"""

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.auth import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import (
    AdminPublic,
    UserCreate,
    UserGroupPublic,
    UserPublic,
)
from daas_auth.domain import accounts
from daas_auth.domain.accounts import ADMINS
from daas_auth.models import User, UserGroup, UserToUserGroup

# In PHP every route here needs the admin scope (security: oauth2-user admin).
router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@router.post("/user")
def user_create(
    body: UserCreate, session: DbSession, actor: Acting, at: Now
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
        actor=actor,
        now=at,
    )
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user.id))


@router.get("/users")
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


@router.get("/user/{user_id}")
def user_get(user_id: int, session: DbSession) -> AdminPublic | UserPublic:
    """
    One account. As in PHP, an admin's id gives the admin's shape.
    """
    account = accounts.find_account(session, user_id)
    if accounts.is_admin(session, user_id):
        return AdminPublic.model_validate(account)
    return UserPublic.of(account, accounts.group_ids(session, user_id))


@router.get("/admins")
def admin_list(session: DbSession) -> list[AdminPublic]:
    """
    Every admin, by id.
    """
    admins = session.scalars(select(User).where(User.id.in_(ADMINS)).order_by(User.id))
    return [AdminPublic.model_validate(admin) for admin in admins]


@router.get("/user_groups")
def user_group_list(session: DbSession) -> list[UserGroupPublic]:
    """
    Every user group, by id.
    """
    groups = session.scalars(select(UserGroup).order_by(UserGroup.id))
    return [UserGroupPublic.model_validate(group) for group in groups]
