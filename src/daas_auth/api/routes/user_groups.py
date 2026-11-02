from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import DbSession, require_scope
from daas_auth.api.schemas import UserGroupPublic
from daas_auth.models import UserGroup

router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@router.get("/user_groups")
def user_group_list(session: DbSession) -> list[UserGroupPublic]:
    """
    Every user group, by id.
    """
    groups = session.scalars(select(UserGroup).order_by(UserGroup.id))
    return [UserGroupPublic.model_validate(group) for group in groups]
