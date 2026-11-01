"""The OAuth routes of PHP's OAuth2HttpController, at the same paths."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from daas_auth.api.auth import AuthCaller, DbSession, Now, require_scope
from daas_auth.domain.grants import token_response

public_router = APIRouter()  # the login itself can't need a token
router = APIRouter()  # app.py adds the bearer check to every route here


async def raw_body(request: Request) -> str:
    # async, because reading the body awaits; the route itself stays sync
    return (await request.body()).decode(errors="replace")


RawBody = Annotated[str, Depends(raw_body)]


@public_router.post("/oauth2/user/token")
def token(body: RawBody, request: Request, session: DbSession, at: Now) -> Response:
    """
    Behind nginx, request.client is the browser (uvicorn's proxy headers);
    Quart calls 127.0.0.1 directly.
    """
    source_ip = request.client.host if request.client else None
    answer = token_response(
        session, uri=str(request.url), body=body, now=at, source_ip=source_ip
    )
    return Response(answer.body, answer.status, answer.headers)


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
