from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import UserGroupCreate, UserGroupPublic, UserGroupUpdate
from daas_auth.domain import user_groups
from daas_auth.models import UserGroup

admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@admin_router.get("/user_groups")
def user_group_list(session: DbSession) -> list[UserGroupPublic]:
    """
    Every user group, by id.
    """
    groups = session.scalars(select(UserGroup).order_by(UserGroup.id))
    return [UserGroupPublic.model_validate(group) for group in groups]


@admin_router.post("/user_group")
def user_group_create(
    body: UserGroupCreate, session: DbSession, actor: Acting, at: Now
) -> UserGroupPublic:
    group = user_groups.create_user_group(
        session, description=body.description, actor=actor, now=at
    )
    session.commit()
    return UserGroupPublic.model_validate(group)


@admin_router.patch("/user_group/{group_id}")
def user_group_update(
    group_id: int, body: UserGroupUpdate, session: DbSession, actor: Acting, at: Now
) -> UserGroupPublic:
    group = user_groups.update_user_group(
        session,
        group_id,
        description=body.description,
        user_ids=body.user_ids,
        actor=actor,
        now=at,
    )
    session.commit()
    return UserGroupPublic.model_validate(group)


@admin_router.delete("/user_group/{group_id}")
def user_group_delete(group_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    """
    Not in PHP. Members and desktop groups lose the group, and stay.
    """
    user_groups.delete_user_group(session, group_id, actor=actor, now=at)
    session.commit()
    return "User group deleted"  # like PHP's other deletes, a JSON string
