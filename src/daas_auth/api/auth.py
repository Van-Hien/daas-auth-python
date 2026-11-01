"""
What a route asks for to get a database session, the time and the caller.
"""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from daas_auth.domain.bearer import Caller, authenticate
from daas_auth.domain.errors import insufficient_scope


def get_session(request: Request) -> Iterator[Session]:
    # One session per request, closed afterwards; it commits only if a route says so.
    with Session(request.app.state.engine) as session:
        yield session


def now() -> datetime:
    # UTC without a time zone, as the columns store it. A test can override this.
    return datetime.now(UTC).replace(tzinfo=None)


DbSession = Annotated[Session, Depends(get_session)]
Now = Annotated[datetime, Depends(now)]


def authenticated(request: Request, session: DbSession, at: Now) -> Caller:
    return authenticate(session, request.headers.get("Authorization"), at)


AuthCaller = Annotated[Caller, Depends(authenticated)]


def require_scope(scope: str) -> Callable[[Caller], Caller]:
    """
    A route that needs `scope` lists Depends(require_scope(scope)).
    """

    def check(caller: AuthCaller) -> Caller:
        if scope not in caller.scopes:
            raise insufficient_scope(scope)
        return caller

    return check
