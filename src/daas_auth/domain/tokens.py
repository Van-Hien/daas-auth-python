"""
Opaque tokens: a random string for the client, its SHA-256 in oauth2_tokens.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from daas_auth.models import OAuth2Token

# Lifetimes
# Access: short. 2 h, not 15 min, because the frontend refreshes on a fixed
# 1 h timer (App.js:88-148) and never reads expires_in.
ACCESS_TTL = timedelta(hours=2)
# Refresh: a refresh token that is not used after REFRESH_TTL dies.
REFRESH_TTL = timedelta(hours=2)
# Session: no token of a login lives past this, however often it is refreshed.
SESSION_MAX = timedelta(hours=8)


def hash_token(token: str) -> str:
    # A token has 256 random bits, so a fast hash is enough; a slow one is for passwords.
    return hashlib.sha256(token.encode()).hexdigest()  # 64 hex characters


@dataclass(frozen=True)
class IssuedPair:
    """
    What the client gets once. Only the hashes stay in the database.
    """

    access_token: str
    refresh_token: str
    expires_in: int


def issue_pair(
    session: Session,
    *,
    user_id: int,
    client_id: str,
    scopes: list[str],
    family_id: int | None,
    now: datetime,
) -> IssuedPair:
    """
    Add one oauth2_tokens row. family_id None starts a new family (a login).
    """
    # 32 random bytes, 43 characters
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    row = OAuth2Token(
        family_id=family_id,
        user_id=user_id,
        client_id=client_id,
        # separated by spaces (RFC 6749 §3.3)
        scopes=" ".join(scopes),
        access_token_hash=hash_token(access_token),
        access_expires_at=now + ACCESS_TTL,
        refresh_token_hash=hash_token(refresh_token),
        refresh_expires_at=now + REFRESH_TTL,
        created_at=now,
        created_by=user_id,
        updated_at=now,
        updated_by=user_id,
    )
    session.add(row)
    if family_id is None:
        # the INSERT runs now, so row.id is known
        session.flush()
        # the first row of a login names its family
        row.family_id = row.id
    return IssuedPair(access_token, refresh_token, int(ACCESS_TTL.total_seconds()))
