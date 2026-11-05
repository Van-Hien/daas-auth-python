"""
Refusals of a request to a protected route, such as GET /oauth2/user/session.

The client learns why in the WWW-Authenticate header, for example

    WWW-Authenticate: Bearer error="invalid_token", error_description="..."

and the body repeats the same fields as JSON. A request without a token gets
only "Bearer", with no error: it just did not know a token was needed.

The token endpoint's refusals (wrong password, ...) are not here: oauthlib
builds those (domain/grants.py).

Refused is every other refusal (an unknown id, a duplicate email, ...);
api/errors.py answers it as problem details.
"""

from collections.abc import Mapping


class Refused(Exception):
    def __init__(
        self, status: int, detail: str, headers: Mapping[str, str] | None = None
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.headers = headers


def refuse_unknown(wanted: list[int], known: set[int], what: str) -> None:
    """
    422 for ids sent that name no row: a relation is never dropped silently.
    """
    unknown = [one for one in wanted if one not in known]
    if unknown:
        listed = ", ".join(str(one) for one in unknown)
        raise Refused(422, f"No {what} has the id {listed}.")


class BearerError(Exception):
    def __init__(
        self,
        status: int,
        error: str | None = None,
        description: str | None = None,
        *,
        scope: str | None = None,
    ) -> None:
        super().__init__(error or "no token")
        self.status = status
        self.fields = {
            name: value
            for name, value in (
                ("error", error),
                ("error_description", description),
                ("scope", scope),
            )
            if value is not None
        }

    def challenge(self) -> str:
        """The WWW-Authenticate header's value."""
        params = ", ".join(f'{name}="{value}"' for name, value in self.fields.items())
        return f"Bearer {params}" if params else "Bearer"


def no_token() -> BearerError:
    return BearerError(401)


def invalid_token(description: str) -> BearerError:
    return BearerError(401, "invalid_token", description)


def insufficient_scope(needed: str) -> BearerError:
    return BearerError(
        403,
        "insufficient_scope",
        f"This route needs the scope {needed!r}.",
        scope=needed,
    )
