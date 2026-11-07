"""
The bearer check every protected route runs.
"""

import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.errors import BearerError, invalid_token, no_token
from daas_auth.domain.tokens import hash_token
from daas_auth.models import OAuth2Token, User

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Caller:
    """
    Who sent the request, and what their token allows.
    """

    user: User
    scopes: tuple[str, ...]


def authenticate(session: Session, authorization: str | None, now: datetime) -> Caller:
    # "Bearer <token>"; the scheme's name is case-insensitive.
    scheme, _, token = (authorization or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise no_token()
    row = session.scalars(
        select(OAuth2Token).where(OAuth2Token.access_token_hash == hash_token(token))
    ).one_or_none()
    if row is None:
        raise _refused(token, "unknown", "The access token is unknown.")
    if row.revoked_at is not None:
        raise _refused(token, "revoked", "The access token has been revoked.")
    if row.access_expires_at <= now:
        raise _refused(token, "expired", "The access token has expired.")
    # The foreign key deletes a user's tokens with the user, so the user exists.
    user = session.get_one(User, row.user_id)
    if not user.enabled:  # checked on every request, so disabling acts at once
        raise _refused(token, "disabled", "The account is disabled.")
    return Caller(user, tuple(row.scopes.split()))


def _refused(token: str, reason: str, description: str) -> BearerError:
    # The start of the hash finds the row in oauth2_tokens; the token stays out of the log.
    log.warning("bearer refused: %s, hash %s", reason, hash_token(token)[:12])
    return invalid_token(description)
