"""
The bearer check every protected route runs (RFC 6750), in PHP's order.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.errors import access_denied
from daas_auth.domain.tokens import hash_token
from daas_auth.models import OAuth2Token, User


@dataclass(frozen=True)
class Caller:
    """
    Who sent the request, and what their token allows.
    """

    user: User
    scopes: tuple[str, ...]


def authenticate(session: Session, authorization: str | None, now: datetime) -> Caller:
    if not authorization:
        raise access_denied('Missing "Authorization" header')
    # Like league (BearerTokenValidator.php), "Bearer " is cut off if it is there.
    token = authorization.strip().removeprefix("Bearer ").strip()
    row = session.scalars(
        select(OAuth2Token).where(OAuth2Token.access_token_hash == hash_token(token))
    ).one_or_none()
    if row is None or row.access_expires_at <= now:
        raise access_denied("Access token could not be verified")
    if row.revoked_at is not None:
        raise access_denied("Access token has been revoked")
    # The foreign key deletes a user's tokens with the user, so the user exists.
    user = session.get_one(User, row.user_id)
    if not user.enabled:  # checked on every request (OAuth2AuthorizationValidator.php)
        raise access_denied("User disabled")
    return Caller(user, tuple(row.scopes.split()))
