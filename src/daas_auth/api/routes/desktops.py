from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import DesktopCreate, DesktopPublic, DesktopUpdate
from daas_auth.domain import desktops
from daas_auth.models import Desktop, DesktopToDesktopGroup

# In PHP every route here needs the admin scope.
admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@admin_router.get("/desktops")
def desktop_list(session: DbSession) -> list[DesktopPublic]:
    """
    Every desktop, by id.
    """
    groups: defaultdict[int, list[int]] = defaultdict(list)
    links = select(
        DesktopToDesktopGroup.desktop_id, DesktopToDesktopGroup.desktop_group_id
    )
    for desktop_id, group_id in session.execute(
        links.order_by(DesktopToDesktopGroup.desktop_group_id)
    ):
        groups[desktop_id].append(group_id)
    found = session.scalars(select(Desktop).order_by(Desktop.id))
    return [DesktopPublic.of(desktop, groups[desktop.id]) for desktop in found]


@admin_router.post("/desktop")
def desktop_create(
    body: DesktopCreate, session: DbSession, actor: Acting, at: Now
) -> DesktopPublic:
    desktop = desktops.create_desktop(
        session,
        description=body.description,
        name=body.name,
        quart_object_id=body.quart_object_id,
        groups=body.groups,
        actor=actor,
        now=at,
    )
    session.commit()
    return DesktopPublic.of(desktop, desktops.group_ids(session, desktop.id))


@admin_router.get("/desktop/{desktop_id}")
def desktop_get(desktop_id: int, session: DbSession) -> DesktopPublic:
    desktop = desktops.find_desktop(session, desktop_id)
    return DesktopPublic.of(desktop, desktops.group_ids(session, desktop.id))


@admin_router.patch("/desktop/{desktop_id}")
def desktop_update(
    desktop_id: int, body: DesktopUpdate, session: DbSession, actor: Acting, at: Now
) -> DesktopPublic:
    """
    Not in PHP: it is how an admin links an imported desktop to its Quart object.
    """
    desktop = desktops.update_desktop(
        session,
        desktop_id,
        description=body.description,
        name=body.name,
        quart_object_id=body.quart_object_id,
        groups=body.groups,
        actor=actor,
        now=at,
    )
    session.commit()
    return DesktopPublic.of(desktop, desktops.group_ids(session, desktop.id))


@admin_router.delete("/desktop/{desktop_id}")
def desktop_delete(desktop_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    """
    Not in PHP. Its desktop groups lose it, and stay.
    """
    desktops.delete_desktop(session, desktop_id, actor=actor, now=at)
    session.commit()
    return "Desktop deleted"  # like PHP's other deletes, a JSON string
