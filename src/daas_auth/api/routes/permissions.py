"""
Quart's third call. PHP's permission tables were never filled and are not carried
over, so no function has a permission here: every answer is PHP's 400.
"""

from fastapi import APIRouter, Depends

from daas_auth.api.dependencies import require_scope
from daas_auth.domain.errors import Refused

admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@admin_router.get("/permissions/{function_name}/{user_id}")
def permission(function_name: str, user_id: int) -> None:
    raise Refused(400, f"No permission is defined for {function_name!r}.")
