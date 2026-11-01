from fastapi import Request
from fastapi.responses import JSONResponse

from daas_auth.domain.errors import OAuthError


def oauth_error_response(_: Request, error: Exception) -> JSONResponse:
    """
    Every OAuthError becomes league's body, with the error's status.
    """
    # app.py registers it for OAuthError only
    if not isinstance(error, OAuthError):
        raise error
    return JSONResponse(error.payload(), status_code=error.status)
