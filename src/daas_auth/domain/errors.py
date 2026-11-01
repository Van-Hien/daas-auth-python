"""
Error responses for refused requests (wrong password, invalid token, ...).

The old PHP backend used the PHP library league/oauth2-server for OAuth2.
When a request was refused, that library sent a JSON body, for example:

    {"error": "invalid_grant",
     "error_description": "The user credentials were incorrect.",
     "message": "The user credentials were incorrect."}

The browser and Quart already read these fields. So this module sends the
same fields with the same texts, copied from league's
OAuthServerException.php (in PHP's vendor/ folder). An user then sees the
same error message before and after the switch from PHP to Python.
"""


class OAuthError(Exception):
    """
    One refused request. The API turns it into a JSON body with this status.
    """

    def __init__(
        self,
        status: int,
        error: str,
        description: str,
        hint: str | None = None,
        *,
        reason: str | None = None,
    ) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.description = description
        self.hint = hint
        # For activity_log only, never sent
        self.reason = reason or error

    def payload(self) -> dict[str, str]:
        body = {"error": self.error, "error_description": self.description}

        if self.hint is not None:
            body["hint"] = self.hint

        # league's old name for error_description, still sent; the suite checks it.
        body["message"] = self.description
        return body


def invalid_request(parameter: str, *, reason: str | None = None) -> OAuthError:
    return OAuthError(
        400,
        "invalid_request",
        "The request is missing a required parameter, includes an invalid parameter"
        " value, includes a parameter more than once, or is otherwise malformed.",
        f"Check the `{parameter}` parameter",
        reason=reason,
    )


def invalid_client() -> OAuthError:
    return OAuthError(401, "invalid_client", "Client authentication failed")


def invalid_scope(scope: str) -> OAuthError:
    return OAuthError(
        400,
        "invalid_scope",
        "The requested scope is invalid, unknown, or malformed",
        f"Check the `{scope}` scope",
    )


def invalid_credentials(*, reason: str) -> OAuthError:
    return OAuthError(
        400, "invalid_grant", "The user credentials were incorrect.", reason=reason
    )


def invalid_refresh_token(hint: str, *, reason: str) -> OAuthError:
    # 401 and invalid_request are league's choice; RFC 6749 §5.2 would say 400 invalid_grant.
    return OAuthError(
        401, "invalid_request", "The refresh token is invalid.", hint, reason=reason
    )


def access_denied(hint: str, *, reason: str | None = None) -> OAuthError:
    return OAuthError(
        401,
        "access_denied",
        "The resource owner or authorization server denied the request.",
        hint,
        reason=reason,
    )


def unsupported_grant_type() -> OAuthError:
    return OAuthError(
        400,
        "unsupported_grant_type",
        "The authorization grant type is not supported by the authorization server.",
        "Check that all required parameters have been provided",
    )


def insufficient_permissions(needed: str, held: tuple[str, ...]) -> OAuthError:
    # PHP's own error, not league's (OAuth2AccessControlMiddleware.php:206-215).
    return OAuthError(
        403,
        "insufficient_permissions",
        "Not allowed to access the requested endpoint (but the access token was valid)",
        f'Invalid scopes, need one of "{needed}" but the token only contains'
        f' "{",".join(held)}"',
    )
