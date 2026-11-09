"""The OAuth routes of PHP's OAuth2HttpController, at the same paths."""

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from daas_auth.api.dependencies import AuthCaller, DbSession, Now, require_scope
from daas_auth.domain.grants import revocation_response, token_response

public_router = APIRouter()  # the login itself can't need a token
router = APIRouter()  # app.py adds the bearer check to every route here
# Argon2id takes 19 MiB and one CPU core per hash. At most 4 logins hash at once,
# in 4 threads of their own that live as long as the process. glibc keeps a freed
# 19 MiB buffer in its thread's arena for reuse, so the memory stays at 4 buffers;
# on anyio's shared pool, whose threads come and go, it grew with each new thread.
# Logins beyond 4 wait without a thread, so the shared pool stays free for the bearer check.
_HASHING = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hashing")


async def in_hashing_thread[T](run: Callable[[], T]) -> T:
    future = asyncio.get_running_loop().run_in_executor(_HASHING, run)
    try:
        return await asyncio.shield(future)
    finally:
        # Cancelled while hashing: the thread still uses the request's session,
        # so let it finish before the session is closed.
        if not future.done():
            await asyncio.wait([future])


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
    answer = await in_hashing_thread(run)

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
