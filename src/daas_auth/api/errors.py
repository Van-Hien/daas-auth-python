from collections.abc import Mapping
from http import HTTPStatus

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from daas_auth.domain.errors import BearerError, Refused

# RFC 9457's media type for an error body outside OAuth
PROBLEM = "application/problem+json"


def bearer_error_response(_: Request, error: Exception) -> JSONResponse:
    """
    RFC 6750's shape
    Every BearerError becomes its status, its WWW-Authenticate header and a JSON body.
    """
    # app.py registers it for BearerError only
    if not isinstance(error, BearerError):
        raise error
    return JSONResponse(
        error.fields,
        status_code=error.status,
        headers={"WWW-Authenticate": error.challenge()},
    )


def problem(
    status: int, detail: str | None = None, headers: Mapping[str, str] | None = None
) -> JSONResponse:
    """
    A refusal as problem details: "about:blank" says the status alone explains it.
    """
    body: dict[str, object] = {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
    }
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, headers=headers, media_type=PROBLEM)


def http_error_response(_: Request, error: Exception) -> JSONResponse:
    """
    404, 405 and every HTTPException a route raises. Starlette's class, so FastAPI's
    subclass is caught too.
    """
    if not isinstance(error, HTTPException):
        raise error
    # Without a detail of its own, Starlette repeats the title; send it once.
    detail = (
        error.detail if error.detail != HTTPStatus(error.status_code).phrase else None
    )
    return problem(error.status_code, detail, error.headers)


def refused_response(_: Request, error: Exception) -> JSONResponse:
    """
    What domain/ refuses: an unknown id, a duplicate email, ...
    """
    # app.py registers it for Refused only
    if not isinstance(error, Refused):
        raise error
    return problem(error.status, error.detail, error.headers)


def validation_error_response(_: Request, error: Exception) -> JSONResponse:
    """
    A body or parameter that fails validation: 400, not FastAPI's 422.
    """
    if not isinstance(error, RequestValidationError):
        raise error
    # Where and what, never the input itself: it can be a password.
    detail = "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.errors()
    )
    return problem(400, detail)
