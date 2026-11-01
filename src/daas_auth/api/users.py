"""
User-related endpoints for admin dashboard
"""

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.auth import DbSession, require_scope
from daas_auth.models import Role, User, UserGroup, UserRole, UserToUserGroup

# In PHP every route here needs the admin scope (security: oauth2-user admin).
router = APIRouter(dependencies=[Depends(require_scope("admin"))])

# The API shows one role per account: admin if it holds that role, else user.
ADMINS = select(UserRole.user_id).join(Role).where(Role.name == "admin")


@router.get("/users")
def user_list(session: DbSession) -> list[dict[str, object]]:
    """
    Every account that is not an admin, as PHP's User entities, by id.
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
    return [
        {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": "user",
            "groups": groups[user.id],
            "enabled": user.enabled,
        }
        for user in users
    ]


@router.get("/admins")
def admin_list(session: DbSession) -> list[dict[str, object]]:
    """
    Every admin, by id.
    """
    admins = session.scalars(select(User).where(User.id.in_(ADMINS)).order_by(User.id))
    return [
        {"id": admin.id, "name": admin.name, "email": admin.email, "role": "admin"}
        for admin in admins
    ]


@router.get("/user_groups")
def user_group_list(session: DbSession) -> list[dict[str, object]]:
    """
    Every user group, by id.
    """
    groups = session.scalars(select(UserGroup).order_by(UserGroup.id))
    return [{"id": group.id, "description": group.description} for group in groups]
