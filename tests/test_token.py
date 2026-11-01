import hashlib
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.tokens import hash_token
from daas_auth.models import ActivityLog, OAuth2Client, OAuth2Token, User

URL = "/oauth2/user/token"
# Made by PHP 8.2.35 (tests/test_passwords.py): bcrypt of "spike-password".
PHP_HASH = "$2y$10$2OldAygisW3L2yAWzS4QmOsQL4TpIasMQJIqgchz57CjiKJ/zOXzS"
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def last_log(app: FastAPI) -> ActivityLog:
    with Session(app.state.engine) as session:
        newest = select(ActivityLog).order_by(ActivityLog.id.desc()).limit(1)
        return session.scalars(newest).one()


def test_login_returns_a_pair_and_stores_only_hashes(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    response = client.post(URL, data=admin_login | {"username": " Admin@X.de"})
    assert response.status_code == 200
    assert (response.headers["Cache-Control"], response.headers["Pragma"]) == (
        "no-store",
        "no-cache",
    )
    body = response.json()
    assert body.keys() == {
        "token_type",
        "expires_in",
        "access_token",
        "refresh_token",
        "scope",
    }
    assert (body["token_type"], body["expires_in"], body["scope"]) == (
        "Bearer",
        7200,
        "admin",
    )

    with Session(app.state.engine) as session:
        row = session.scalars(select(OAuth2Token)).one()
    assert row.access_token_hash == hash_token(body["access_token"])
    assert row.refresh_token_hash == hash_token(body["refresh_token"])
    assert (row.family_id, row.scopes) == (row.id, "admin")  # a login starts a family
    log = last_log(app)
    assert (log.action, log.result, log.actor_email) == ("login", "ok", "admin@x.de")
    assert (log.target_table, log.target_id, log.source_ip) == (
        "users",
        row.user_id,
        "testclient",
    )

    caller = client.get(
        "/oauth2/user/session",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert caller.json()["scopes"] == ["admin"]


@pytest.mark.parametrize(
    ("changes", "status", "error", "reason"),
    [
        ({"password": "wrong"}, 400, "invalid_grant", "wrong_password"),
        ({"username": "nobody@x.de"}, 400, "invalid_grant", "unknown_user"),
        ({"username": ""}, 400, "invalid_request", "invalid_request"),
        ({"client_id": ""}, 401, "invalid_client", "invalid_client"),
        ({"client_id": "nope"}, 401, "invalid_client", "invalid_client"),
        ({"client_secret": "x"}, 401, "invalid_client", "invalid_client"),
        ({"scope": ""}, 400, "invalid_scope", "invalid_scope"),
        ({"scope": "expert"}, 400, "invalid_scope", "invalid_scope"),
        # R-1, fixed: the admin on the User tab learns why, instead of a bare 401.
        ({"scope": "user"}, 400, "invalid_scope", "invalid_scope"),
        ({"grant_type": "client_credentials"}, 400, "unsupported_grant_type", None),
    ],
)
def test_a_refused_login_says_why_and_is_logged(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    changes: dict[str, str],
    status: int,
    error: str,
    reason: str | None,
) -> None:
    response = client.post(URL, data=admin_login | changes)
    assert (response.status_code, response.json()["error"]) == (status, error)
    assert response.json().keys() <= {"error", "error_description"}
    log = last_log(app)
    assert (log.result, log.reason) == ("failed", reason or error)
    assert log.actor_email == (changes.get("username", admin_login["username"]) or None)
    with Session(app.state.engine) as session:
        assert session.scalars(select(OAuth2Token)).first() is None


def test_r1_names_the_scope_the_account_lacks(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    response = client.post(URL, data=admin_login | {"scope": "user"})
    assert response.json()["error_description"] == (
        "The account does not hold the scope 'user'."
    )
    # Of several scopes, the token gets those the account holds, and says which.
    response = client.post(URL, data=admin_login | {"scope": "admin user"})
    assert (response.status_code, response.json()["scope"]) == (200, "admin")
    response = client.post(URL, data=admin_login | {"scope": "admin admin"})
    assert (response.status_code, response.json()["scope"]) == (200, "admin")


def test_a_wrong_client_gets_a_challenge(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    response = client.post(URL, data=admin_login | {"client_id": "nope"})
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_client"'


def test_a_disabled_user_gets_no_token(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    add_user("off@x.de", PHP_HASH, enabled=False)
    form = admin_login | {
        "username": "off@x.de",
        "password": "spike-password",
        "scope": "user",
    }
    response = client.post(URL, data=form)
    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": "The account is disabled.",
    }
    assert last_log(app).reason == "disabled"


def test_a_malformed_request_is_refused(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    def error_of(content: str, url: str = URL) -> tuple[int, str]:
        response = client.post(url, content=content, headers=FORM)
        return response.status_code, response.json()["error_description"]

    # No parameter more than once, whichever it is.
    assert error_of("grant_type=password&scope=admin&scope=user") == (
        400,
        "Duplicate scope parameter.",
    )
    assert error_of("grant_type=refresh_token&client_id=a&client_id=b") == (
        400,
        "Duplicate client_id parameter.",
    )
    # A body that is not URL-encoded has no parameters, such as the frontend's
    # refresh with a raw space after "Bearer" (F-7).
    assert error_of("grant_type=refresh_token&refresh_token=Bearer abc") == (
        400,
        "Request is missing grant_type parameter.",
    )
    # Credentials belong in the body, not in the URL, where logs keep them;
    # a malformed query is refused the same way, not with a 500.
    form = "&".join(f"{key}={value}" for key, value in admin_login.items())
    for query in ("?x=1", "?x", "?%zz=1"):
        assert error_of(form, URL + query) == (
            400,
            "URL query parameters are not allowed",
        )


def test_a_php_hash_becomes_argon2id_at_login(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    user_id = add_user("anna@x.de", PHP_HASH)
    form = admin_login | {
        "username": "anna@x.de",
        "password": "spike-password",
        "scope": "user",
    }
    assert client.post(URL, data=form).status_code == 200
    with Session(app.state.engine) as session:
        stored = session.get_one(User, user_id).password
        actions = session.scalars(
            select(ActivityLog.action).where(ActivityLog.target_id == user_id)
        )
        assert actions.all() == ["password_rehash", "login"]
    assert stored.startswith("$argon2id$")
    assert client.post(URL, data=form).status_code == 200  # the new hash verifies


def test_a_refused_login_keeps_no_rehash(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    # Right password, but a scope the account lacks: the rehash is rolled back too.
    user_id = add_user("anna@x.de", PHP_HASH)
    form = admin_login | {"username": "anna@x.de", "password": "spike-password"}
    assert client.post(URL, data=form).status_code == 400
    with Session(app.state.engine) as session:
        assert session.get_one(User, user_id).password == PHP_HASH


def test_a_confidential_client_needs_its_secret(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    with Session(app.state.engine) as session:
        test_client = session.get_one(OAuth2Client, "test-client")
        test_client.secret_hash = hashlib.sha256(b"s3cret").hexdigest()
        session.commit()
    with_secret = admin_login | {"client_secret": "s3cret"}
    assert client.post(URL, data=with_secret).status_code == 200
    assert client.post(URL, data=admin_login).status_code == 401


def test_a_confidential_client_without_a_stored_secret_is_refused(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    with Session(app.state.engine) as session:
        session.get_one(OAuth2Client, "test-client").is_confidential = True
        session.commit()
    for secret in ("", "anything"):
        response = client.post(URL, data=admin_login | {"client_secret": secret})
        assert response.status_code == 401
