from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response

from daas_auth.api.dependencies import Acting, DbSession, Now, require_scope
from daas_auth.api.schemas import (
    RegistrationCode,
)
from daas_auth.domain import accounts

user_router = APIRouter(dependencies=[Depends(require_scope("user"))])
public_router = APIRouter()


@public_router.post("/user/validate_email")
def validate_email(_: RegistrationCode) -> Response:
    """
    No code is ever mailed, so none can match. PHP's answer for a wrong code: an
    empty 400, which says no more than the status.
    """
    return Response(status_code=400)


@user_router.post("/user/request-application/{application}/{language}")
def request_application(
    application: str,
    language: Annotated[str, Path(pattern="^[a-z]{3}$")],
    session: DbSession,
    actor: Acting,
    at: Now,
) -> Response:
    """
    The user dashboard's request for an application, with the page's language.
    """
    accounts.request_application(session, application, language, actor=actor, now=at)
    session.commit()
    return Response(status_code=200)
