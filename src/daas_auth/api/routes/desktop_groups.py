from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import (
    DesktopGroupCreate,
    DesktopGroupPublic,
    UserGroupPublic,
)
from daas_auth.domain import desktop_groups, desktops
from daas_auth.models import DesktopGroup, DesktopToDesktopGroup

# In PHP every route here needs the admin scope.
admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@admin_router.get("/desktop_groups")
def desktop_group_list(session: DbSession) -> list[DesktopGroupPublic]:
    """
    Every desktop group, by id, with its desktops.
    """
    members: defaultdict[int, list[int]] = defaultdict(list)
    links = select(
        DesktopToDesktopGroup.desktop_group_id, DesktopToDesktopGroup.desktop_id
    )
    for group_id, desktop_id in session.execute(
        links.order_by(DesktopToDesktopGroup.desktop_id)
    ):
        members[group_id].append(desktop_id)
    groups = session.scalars(select(DesktopGroup).order_by(DesktopGroup.id))
    return [DesktopGroupPublic.of(group, members[group.id]) for group in groups]


# The frontend posts to /desktop_group, PHP declared /desktop-group (F-3): both work.
@admin_router.post("/desktop_group")
@admin_router.post("/desktop-group")
def desktop_group_create(
    body: DesktopGroupCreate, session: DbSession, actor: Acting, at: Now
) -> DesktopGroupPublic:
    group = desktop_groups.create_desktop_group(
        session,
        description=body.description,
        desktops=body.desktop_ids,
        actor=actor,
        now=at,
    )
    session.commit()
    return DesktopGroupPublic.of(group, desktop_groups.desktop_ids(session, group.id))


@admin_router.get("/desktop_group/{group_id}")
def desktop_group_get(group_id: int, session: DbSession) -> DesktopGroupPublic:
    group = desktop_groups.find_desktop_group(session, group_id)
    return DesktopGroupPublic.of(group, desktop_groups.desktop_ids(session, group.id))


@admin_router.delete("/desktop_group/{group_id}")
def desktop_group_delete(
    group_id: int, session: DbSession, actor: Acting, at: Now
) -> str:
    """
    Not in PHP. Its desktops and user groups lose the group, and stay.
    """
    desktop_groups.delete_desktop_group(session, group_id, actor=actor, now=at)
    session.commit()
    return "Desktop group deleted"  # like PHP's other deletes, a JSON string


@admin_router.post("/desktop_group/{group_id}/user_group/{user_group_id}")
def desktop_group_add_user_group(
    group_id: int, user_group_id: int, session: DbSession, actor: Acting, at: Now
) -> list[UserGroupPublic]:
    """
    PHP's row 21 answered 200 and stored nothing (no flush): here it is stored.
    The answer, as in PHP: the user groups that may now use the desktop group.
    """
    desktop_groups.add_user_group(session, group_id, user_group_id, actor=actor, now=at)
    session.commit()
    return [
        UserGroupPublic.model_validate(group)
        for group in desktop_groups.user_groups_of(session, group_id)
    ]


@admin_router.delete("/desktop_group/{group_id}/user_group/{user_group_id}")
def desktop_group_remove_user_group(
    group_id: int, user_group_id: int, session: DbSession, actor: Acting, at: Now
) -> list[UserGroupPublic]:
    """
    Not in PHP, which could not take access away again (R-3).
    """
    desktop_groups.remove_user_group(
        session, group_id, user_group_id, actor=actor, now=at
    )
    session.commit()
    return [
        UserGroupPublic.model_validate(group)
        for group in desktop_groups.user_groups_of(session, group_id)
    ]


@admin_router.post("/desktop_group/{group_id}/desktop/{desktop_id}")
def desktop_group_add_desktop(
    group_id: int, desktop_id: int, session: DbSession, actor: Acting, at: Now
) -> DesktopGroupPublic:
    """
    Not in PHP: no route could put a desktop into a group (R-3).
    """
    desktops.add_to_group(session, desktop_id, group_id, actor=actor, now=at)
    session.commit()
    group = desktop_groups.find_desktop_group(session, group_id)
    return DesktopGroupPublic.of(group, desktop_groups.desktop_ids(session, group_id))


@admin_router.delete("/desktop_group/{group_id}/desktop/{desktop_id}")
def desktop_group_remove_desktop(
    group_id: int, desktop_id: int, session: DbSession, actor: Acting, at: Now
) -> DesktopGroupPublic:
    desktops.remove_from_group(session, desktop_id, group_id, actor=actor, now=at)
    session.commit()
    group = desktop_groups.find_desktop_group(session, group_id)
    return DesktopGroupPublic.of(group, desktop_groups.desktop_ids(session, group_id))
