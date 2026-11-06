"""
Opaque tokens: a random string for the client, its SHA-256 in oauth2_tokens.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from daas_auth.domain.activity import Action, record
from daas_auth.models import OAuth2Token

# Lifetimes
# Access: short. 2 h, not 15 min, because the frontend refreshes on a fixed
# 1 h timer and never reads expires_in.
ACCESS_TTL = timedelta(hours=2)
# Refresh: a refresh token that is not used after REFRESH_TTL dies.
REFRESH_TTL = timedelta(hours=2)
# Session: no token of a login lives past this, however often it is refreshed.
SESSION_MAX = timedelta(hours=8)


def new_token(_: object = None) -> str:
    # 32 random bytes, 43 characters. oauthlib calls it with its request.
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    # A token has 256 random bits, so a fast hash is enough; a slow one is for passwords.
    return hashlib.sha256(token.encode()).hexdigest()  # 64 hex characters


@dataclass(frozen=True)
class Expiry:
    access: datetime
    refresh: datetime


def expiry(now: datetime, session_ends: datetime) -> Expiry:
    """
    When a pair issued now dies: its own lifetime, or the session's end if sooner.
    """
    return Expiry(
        access=min(now + ACCESS_TTL, session_ends),
        refresh=min(now + REFRESH_TTL, session_ends),
    )


def save_pair(
    session: Session,
    *,
    access_token: str,
    refresh_token: str,
    user_id: int,
    client_id: str,
    scopes: list[str],
    family_id: int | None,
    now: datetime,
    expires: Expiry,
) -> OAuth2Token:
    """
    Add one oauth2_tokens row. family_id None starts a new family (a login).
    """
    row = OAuth2Token(
        family_id=family_id,
        user_id=user_id,
        client_id=client_id,
        # separated by spaces, as OAuth sends them
        scopes=" ".join(scopes),
        access_token_hash=hash_token(access_token),
        access_expires_at=expires.access,
        refresh_token_hash=hash_token(refresh_token),
        refresh_expires_at=expires.refresh,
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
    return row


def purge_tokens(session: Session, now: datetime) -> int:
    """
    Delete the rows of finished logins; the caller commits.

    A row outlives its own expiry: a used refresh token must be recognised for as
    long as its login can still hold a live pair. No login lasts past SESSION_MAX,
    so a row that expired SESSION_MAX ago has no live relative left.
    """
    finished = OAuth2Token.refresh_expires_at < now - SESSION_MAX
    count = session.execute(
        select(func.count()).select_from(OAuth2Token).where(finished)
    ).scalar_one()
    session.execute(delete(OAuth2Token).where(finished))
    record(
        session,
        Action.TOKEN_PURGE,
        ok=True,
        now=now,
        target_table="oauth2_tokens",
        details=f"{count} rows deleted",
    )
    return count
