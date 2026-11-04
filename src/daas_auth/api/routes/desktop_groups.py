from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import DesktopGroupCreate, DesktopGroupPublic
from daas_auth.domain import desktop_groups
from daas_auth.models import DesktopGroup, DesktopToDesktopGroup

# In PHP every route here needs the admin scope.
admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


def _public(group: DesktopGroup, desktop_ids: list[int]) -> DesktopGroupPublic:
    return DesktopGroupPublic(
        id=group.id, description=group.description, desktopIds=desktop_ids
    )


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
    return [_public(group, members[group.id]) for group in groups]


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
    return _public(group, desktop_groups.desktop_ids(session, group.id))


@admin_router.get("/desktop_group/{group_id}")
def desktop_group_get(group_id: int, session: DbSession) -> DesktopGroupPublic:
    group = desktop_groups.find_desktop_group(session, group_id)
    return _public(group, desktop_groups.desktop_ids(session, group.id))


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
