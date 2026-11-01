from fastapi import Request
from fastapi.responses import JSONResponse

from daas_auth.domain.errors import BearerError


def bearer_error_response(_: Request, error: Exception) -> JSONResponse:
    """
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
