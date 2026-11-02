"""
User-related endpoints for admin dashboard
"""

from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response
from sqlalchemy import select

from daas_auth.api.auth import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import (
    AdminCreate,
    AdminPublic,
    Message,
    RegistrationCode,
    UserCreate,
    UserGroupPublic,
    UserPublic,
    UserUpdate,
)
from daas_auth.domain import accounts
from daas_auth.domain.accounts import ADMINS
from daas_auth.models import User, UserGroup, UserToUserGroup

# In PHP every route here needs the admin scope (security: oauth2-user admin).
router = APIRouter(dependencies=[Depends(require_scope("admin"))])
# The user dashboard's routes, and the registration page's: anyone may call it.
user_router = APIRouter(dependencies=[Depends(require_scope("user"))])
public_router = APIRouter()


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


@router.patch("/user/{user_id}")
def user_update(
    user_id: int, body: UserUpdate, session: DbSession, actor: Acting, at: Now
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
        actor=actor,
        now=at,
    )
    session.commit()
    return Message(message="User updated")


@router.post("/user/{user_id}/enable")
def user_enable(user_id: int, session: DbSession, actor: Acting, at: Now) -> UserPublic:
    user = accounts.set_enabled(session, user_id, True, actor=actor, now=at)
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user_id))


@router.post("/user/{user_id}/disable")
def user_disable(
    user_id: int, session: DbSession, actor: Acting, at: Now
) -> UserPublic:
    user = accounts.set_enabled(session, user_id, False, actor=actor, now=at)
    session.commit()
    return UserPublic.of(user, accounts.group_ids(session, user_id))


@router.delete("/user/{user_id}")
def user_delete(user_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    accounts.delete_user(session, user_id, actor=actor, now=at)
    session.commit()
    return "User deleted"  # PHP's answer, a JSON string


@router.get("/admins")
def admin_list(session: DbSession) -> list[AdminPublic]:
    """
    Every admin, by id.
    """
    admins = session.scalars(select(User).where(User.id.in_(ADMINS)).order_by(User.id))
    return [AdminPublic.model_validate(admin) for admin in admins]


@router.post("/admin")
def admin_create(
    body: AdminCreate, session: DbSession, actor: Acting, at: Now
) -> AdminPublic:
    admin = accounts.create_account(
        session,
        name=body.name,
        email=body.email,
        password=body.password,
        role="admin",
        groups=[],
        actor=actor,
        now=at,
    )
    session.commit()
    return AdminPublic.model_validate(admin)


@router.delete("/admin/{admin_id}")
def admin_delete(admin_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    accounts.delete_admin(session, admin_id, actor=actor, now=at)
    session.commit()
    return "admin deleted"  # PHP's answer, a JSON string


@router.get("/user_groups")
def user_group_list(session: DbSession) -> list[UserGroupPublic]:
    """
    Every user group, by id.
    """
    groups = session.scalars(select(UserGroup).order_by(UserGroup.id))
    return [UserGroupPublic.model_validate(group) for group in groups]


@public_router.post("/user/validate_email")
def validate_email(_: RegistrationCode) -> Response:
    """
    No code is ever mailed, so none can match. PHP's answer for a wrong code: an
    empty 400, which says no more than the status.
    """
    return Response(status_code=400)


@user_router.post("/user/request-application/{application}/{language}")
def request_application(
    application: str,
    language: Annotated[str, Path(pattern="^[a-z]{3}$")],
    session: DbSession,
    actor: Acting,
    at: Now,
) -> Response:
    """
    The user dashboard's request for an application, with the page's language.
    """
    accounts.request_application(session, application, language, actor=actor, now=at)
    session.commit()
    return Response(status_code=200)
