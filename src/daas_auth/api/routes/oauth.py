"""The OAuth routes of PHP's OAuth2HttpController, at the same paths."""

from functools import partial
from typing import Annotated

import anyio
from anyio.to_thread import run_sync
from fastapi import APIRouter, Depends, Request, Response

from daas_auth.api.dependencies import AuthCaller, DbSession, Now, require_scope
from daas_auth.domain.grants import revocation_response, token_response

public_router = APIRouter()  # the login itself can't need a token
router = APIRouter()  # app.py adds the bearer check to every route here
# Argon2id takes 19 MiB and one CPU core per hash. At most 4 logins hash at once;
# the others wait in the event loop, so the thread pool stays free for the bearer check.
_HASHING = anyio.CapacityLimiter(4)


async def raw_body(request: Request) -> str:
    # async, because reading the body awaits
    return (await request.body()).decode(errors="replace")


RawBody = Annotated[str, Depends(raw_body)]


@public_router.post("/oauth2/user/token")
async def token(
    body: RawBody, request: Request, session: DbSession, at: Now
) -> Response:
    """
    Behind nginx, request.client is the browser (uvicorn's proxy headers);
    Quart calls 127.0.0.1 directly.
    """
    source_ip = request.client.host if request.client else None
    run = partial(
        token_response,
        session,
        uri=str(request.url),
        body=body,
        now=at,
        source_ip=source_ip,
    )
    answer = await run_sync(run, limiter=_HASHING)

    return Response(answer.body, answer.status, answer.headers)


@public_router.post("/oauth2/user/revoke")
def revoke(body: RawBody, request: Request, session: DbSession, at: Now) -> Response:
    """
    The frontend's logout. The token in the body is the proof, so no bearer.
    """
    source_ip = request.client.host if request.client else None
    answer = revocation_response(
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
