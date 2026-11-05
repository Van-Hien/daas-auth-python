"""
POST /oauth2/user/token: the password grant, run by oauthlib.

oauthlib does the protocol: which parameters a grant needs, in which order they
are checked, the error codes and the response. It asks the Validator below
about everything stored here: clients, users, scopes and tokens.
"""

import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from oauthlib.common import Request
from oauthlib.oauth2 import LegacyApplicationServer, RequestValidator
from oauthlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    OAuth2Error,
    UnsupportedGrantTypeError,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from daas_auth.domain.activity import Action, record
from daas_auth.domain.emails import normalise_email
from daas_auth.domain.passwords import hash_password, needs_rehash, verify_password
from daas_auth.domain.throttle import refuse_if_throttled
from daas_auth.domain.tokens import (
    SESSION_MAX,
    expiry,
    hash_token,
    new_token,
    save_pair,
)
from daas_auth.models import OAuth2Client, OAuth2Token, Role, User, UserRole

if TYPE_CHECKING:  # the type exists only in the stubs (types-oauthlib)
    from oauthlib.oauth2.rfc6749.request_validator import _BearerToken

SCOPES = ("user", "admin")  # PHP's two (OAuth2ScopeRepository.php:27-35)
# Checked when the email is unknown, so that answer takes as long as a wrong password.
_UNKNOWN_USER_HASH = hash_password("no user has this password")


@dataclass(frozen=True)
class _Client:
    # the only attribute oauthlib reads from request.client
    client_id: str


class Validator(RequestValidator):
    """
    One per request: it holds the request's database session and time, and
    remembers what it found, for the token row and the activity_log row.
    """

    def __init__(self, session: Session, now: datetime) -> None:
        super().__init__()
        self.session = session
        self.now = now
        self.user: User | None = None
        self.client_id: str | None = None
        self.old: OAuth2Token | None = None  # the row a refresh replaces
        self.session_ends = now + SESSION_MAX  # a login starts the session
        self.reason: str | None = None  # why it was refused, for activity_log only
        self.reused_family: int | None = None

    def _refuse(self, reason: str) -> bool:
        self.reason = reason
        return False

    # ---- the client ----------------------------------------------------

    def _client(self, client_id: str | None) -> OAuth2Client | None:
        return self.session.get(OAuth2Client, client_id) if client_id else None

    def client_authentication_required(
        self, request: Request, *args: Any, **kwargs: Any
    ) -> bool:
        # A client with a secret must send it; one that sends a secret is checked.
        client = self._client(request.client_id)
        has_secret = client is not None and (
            client.is_confidential or client.secret_hash is not None
        )
        return has_secret or bool(request.client_secret)

    def authenticate_client(self, request: Request, *args: Any, **kwargs: Any) -> bool:
        client = self._client(request.client_id)
        # A confidential client without a stored secret can't prove who it is.
        if client is None or (client.is_confidential and client.secret_hash is None):
            return self._refuse("invalid_client")
        # Only the secret's hash is stored; compared in constant time.
        secret = request.client_secret or ""
        given = hash_token(secret) if secret else ""
        if not hmac.compare_digest(given, client.secret_hash or ""):
            return self._refuse("invalid_client")
        self.client_id = client.identifier
        request.client = _Client(client.identifier)
        return True

    def authenticate_client_id(
        self, client_id: str, request: Request, *args: Any, **kwargs: Any
    ) -> bool:
        # Reached only for a client without a secret that sent none.
        client = self._client(client_id)
        if client is None:
            return self._refuse("invalid_client")
        self.client_id = client.identifier
        request.client = _Client(client.identifier)
        return True

    def validate_grant_type(
        self,
        client_id: str,
        grant_type: str,
        client: Any,
        request: Request,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        return True  # every client may use every grant, as in PHP

    # ---- the password grant --------------------------------------------

    def validate_user(
        self,
        username: str,
        password: str,
        client: Any,
        request: Request,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        email = normalise_email(username)
        user = self.session.scalars(
            select(User).where(User.email == email)
        ).one_or_none()
        if user is None:
            verify_password(password, _UNKNOWN_USER_HASH)
            return self._refuse("unknown_user")
        if not verify_password(password, user.password):
            return self._refuse("wrong_password")
        if not user.enabled:
            # The password was right, so saying why does not reveal the account.
            self.reason = "disabled"
            raise InvalidGrantError("The account is disabled.", request=request)
        if needs_rehash(user.password):
            # The password is known only now: PHP's bcrypt hash becomes Argon2id.
            user.password = hash_password(password)
            user.updated_at = self.now
            user.updated_by = user.id
            record(
                self.session,
                Action.PASSWORD_REHASH,
                ok=True,
                now=self.now,
                actor_id=user.id,
                actor_email=email,
                target_table="users",
                target_id=user.id,
            )
        self.user = user
        return True

    def get_default_scopes(
        self, client_id: str, request: Request, *args: Any, **kwargs: Any
    ) -> list[str]:
        return []  # no default: a login without scope is refused

    def validate_scopes(
        self,
        client_id: str,
        scopes: list[str],
        client: Any,
        request: Request,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        if not scopes or any(scope not in SCOPES for scope in scopes):
            return self._refuse("invalid_scope")
        held = self._held(self.user)
        # each scope once, in the order asked
        granted = [scope for scope in dict.fromkeys(scopes) if scope in held]
        if not granted:
            # An admin on the User tab learns why, instead of a bare refusal.
            self.reason = "invalid_scope"
            raise InvalidScopeError(
                f"The account does not hold the scope {scopes[0]!r}.", request=request
            )
        request.scopes = granted  # oauthlib issues these and names them in "scope"
        return True

    def _held(self, user: User | None) -> set[str]:
        if user is None:
            raise RuntimeError("scopes are checked after the user")
        roles = select(Role.name).join(UserRole).where(UserRole.user_id == user.id)
        return set(self.session.scalars(roles))

    # ---- the refresh grant ---------------------------------------------

    def validate_refresh_token(
        self,
        refresh_token: str,
        client: Any,
        request: Request,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        # FOR UPDATE: two refreshes with one token run one after the other on MariaDB.
        row = self.session.scalars(
            select(OAuth2Token)
            .where(OAuth2Token.refresh_token_hash == hash_token(refresh_token))
            .with_for_update()
        ).one_or_none()
        if row is None:
            return self._refuse("unknown")
        if row.client_id != client.client_id:
            return self._refuse("other_client")
        if row.revoked_at is not None:
            # Already used: someone holds a copy. The family dies after the rollback.
            self.reused_family = row.family_id
            return self._refuse("reused")
        if row.refresh_expires_at <= self.now:
            return self._refuse("expired")
        user = self.session.get_one(User, row.user_id)
        if not user.enabled:
            return self._refuse("disabled")
        # family_id is the id of the login's row, so its created_at is the login time
        login = self.session.get_one(OAuth2Token, row.family_id)
        self.session_ends = login.created_at + SESSION_MAX
        self.old, self.user = row, user
        return True

    def get_original_scopes(
        self, refresh_token: str, request: Request, *args: Any, **kwargs: Any
    ) -> list[str]:
        # A role taken away since the login does not come back with a refresh.
        if self.old is None:
            raise RuntimeError("scopes are read after the refresh token")
        held = self._held(self.user)
        scopes = [scope for scope in self.old.scopes.split() if scope in held]
        if not scopes:
            self.reason = "invalid_scope"
            raise InvalidScopeError(
                "The account no longer holds a scope of this token.", request=request
            )
        return scopes

    # ---- the token pair --------------------------------------------------

    def expires_in(self, request: Request) -> int:
        return int(
            (expiry(self.now, self.session_ends).access - self.now).total_seconds()
        )

    def save_bearer_token(
        self, token: "_BearerToken", request: Request, *args: Any, **kwargs: Any
    ) -> None:
        if self.user is None or self.client_id is None:
            raise RuntimeError(
                "a token is saved after the client and the user are known"
            )
        family_id = None
        if self.old is not None:
            # One row holds the pair, so this also kills the old access token.
            self.old.revoked_at = self.now
            self.old.updated_at = self.now
            family_id = self.old.family_id
        refresh_token = token.get("refresh_token")
        if refresh_token is None:  # oauthlib adds it whenever the grant issues one
            raise RuntimeError("the password grant always issues a refresh token")
        save_pair(
            self.session,
            access_token=token["access_token"],
            refresh_token=refresh_token,
            user_id=self.user.id,
            client_id=self.client_id,
            scopes=list(request.scopes or []),
            family_id=family_id,
            now=self.now,
            expires=expiry(self.now, self.session_ends),
        )


@dataclass(frozen=True)
class TokenResponse:
    headers: dict[str, str]
    body: str
    status: int


GRANTS = {"password": Action.LOGIN, "refresh_token": Action.TOKEN_REFRESH}


def token_response(
    session: Session, *, uri: str, body: str, now: datetime, source_ip: str | None
) -> TokenResponse:
    """
    Every attempt, refused or not, writes one activity_log row.
    Refused raises only for a throttled login; every other refusal is an OAuth answer.
    """
    validator = Validator(session, now)
    server = LegacyApplicationServer(
        validator, token_generator=new_token, token_expires_in=validator.expires_in
    )
    path = urlsplit(uri)._replace(query="").geturl()
    # oauthlib's own parsing of the body, read here for the checks and the log row
    request = Request(path, "POST", body)
    if request.grant_type == "password":
        refuse_if_throttled(
            session, email=_attempted_email(request), source_ip=source_ip, now=now
        )
    try:
        if path != uri:
            # Credentials belong in the body, not in a URL that logs keep. Refused
            # here, because oauthlib's parser raises ValueError on a malformed query.
            raise InvalidRequestError("URL query parameters are not allowed")
        if request.duplicate_params:  # oauthlib checks only some of them
            raise InvalidRequestError(
                f"Duplicate {request.duplicate_params[0]} parameter."
            )
        if request.grant_type and request.grant_type not in GRANTS:
            # oauthlib would hand it to the password grant, which asks for a username
            raise UnsupportedGrantTypeError()
        headers, answer, status = server.create_token_response(uri, "POST", body)
    except OAuth2Error as error:  # raised before a grant runs
        headers = error.headers | {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        answer, status = error.json, error.status_code
    action = GRANTS.get(request.grant_type or "", Action.LOGIN)
    if status == 200 and validator.user is not None:
        _log_success(session, action, validator.user, now, source_ip)
    else:
        _log_refusal(session, action, validator, request, answer, now, source_ip)
    session.commit()  # a success: the token row, any rehash and the log row together
    return TokenResponse(headers, answer or "", status or 500)


def _attempted_email(request: Request) -> str | None:
    # A refresh has no username, and oauthlib's Request raises on a name it lacks.
    email = normalise_email(getattr(request, "username", None) or "")
    return email[:255] or None  # an attempt may be longer than the column


def _log_success(
    session: Session, action: Action, user: User, now: datetime, source_ip: str | None
) -> None:
    record(
        session,
        action,
        ok=True,
        now=now,
        actor_id=user.id,
        actor_email=user.email,
        target_table="users",
        target_id=user.id,
        source_ip=source_ip,
    )


def _log_refusal(
    session: Session,
    action: Action,
    validator: Validator,
    request: Request,
    answer: str | None,
    now: datetime,
    source_ip: str | None,
) -> None:
    session.rollback()  # nothing of the refused attempt is kept, only its log row
    family = validator.reused_family
    if family is not None:
        # A refresh token used twice: every pair of its login dies, the newest too.
        session.execute(
            update(OAuth2Token)
            .where(OAuth2Token.family_id == family)
            .values(revoked_at=now, updated_at=now)
        )
    record(
        session,
        action,
        ok=False,
        now=now,
        reason=validator.reason or json.loads(answer or "{}").get("error"),
        actor_email=_attempted_email(request),
        source_ip=source_ip,
        details=None if family is None else f"family {family}",
    )
