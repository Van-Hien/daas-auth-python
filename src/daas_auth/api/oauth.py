"""
The OAuth routes of PHP's OAuth2HttpController, at the same paths.
"""

from fastapi import APIRouter, Depends, Response

from daas_auth.api.auth import AuthCaller, require_scope

router = APIRouter()  # app.py adds the bearer check to every route here


@router.get("/oauth2/user/session")
def session_details(caller: AuthCaller) -> dict[str, object]:
    """
    Quart calls it on every request and reads user_id and name.
    """
    return {
        "user_id": caller.user.id,
        "email": caller.user.email,
        "name": caller.user.name,
        "scopes": list(caller.scopes),
    }


# PHP's two debugging routes; the contract suite checks a scope refusal with /ping/user.
@router.get("/ping/user", dependencies=[Depends(require_scope("user"))])
def ping_user() -> Response:
    return Response(status_code=200)


@router.get("/ping/admin", dependencies=[Depends(require_scope("admin"))])
def ping_admin() -> Response:
    return Response(status_code=200)
