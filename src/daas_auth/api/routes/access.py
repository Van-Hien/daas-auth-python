"""
The desktops a caller may use, for Quart (new: PHP's only check compared ids across
tables and had no caller).
Caller can use any valid token; admins may use every desktop.
"""

from fastapi import APIRouter

from daas_auth.api.dependencies import AuthCaller, DbSession
from daas_auth.api.schemas import AllowedDesktopPublic
from daas_auth.domain import access

router = APIRouter()  # app.py adds the bearer check to every route here


@router.get("/oauth2/user/desktops")
def desktop_list(caller: AuthCaller, session: DbSession) -> list[AllowedDesktopPublic]:
    """
    For the dashboard to draw: display only, the per-action check is the next route.
    """
    return [
        AllowedDesktopPublic.model_validate(desktop)
        for desktop in access.allowed_desktops(session, caller.user.id)
    ]


@router.get("/oauth2/user/desktops/{quart_object_id}")
def desktop_check(
    quart_object_id: str, caller: AuthCaller, session: DbSession
) -> AllowedDesktopPublic:
    """
    Quart asks before every action on one of its objects: 200 may, 403 may not,
    404 no desktop is that object.
    """
    desktop = access.check_desktop(session, caller.user.id, quart_object_id)
    return AllowedDesktopPublic.model_validate(desktop)
