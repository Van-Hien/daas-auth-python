from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from daas_auth.api.dependencies import now
from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, OAuth2Client, OAuth2Token, UserRole

URL = "/oauth2/user/token"
LOGIN_TIME = datetime(2026, 11, 2, 9, 0)


def at(app: FastAPI, moment: datetime) -> None:
    app.dependency_overrides[now] = lambda: moment


def login(client: TestClient, admin_login: dict[str, str]) -> dict[str, Any]:
    response = client.post(URL, data=admin_login)
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


def logout(client: TestClient, token: str) -> int:
    # drives the Step-1 revoke route the frontend's logout hits
    return client.post(
        "/oauth2/user/revoke", data={"token": token, "client_id": "test-client"}
    ).status_code


def refresh(client: TestClient, token: str, **changes: str) -> dict[str, Any]:
    form = {"grant_type": "refresh_token", "client_id": "test-client", "scope": "admin"}
    response = client.post(URL, data=form | {"refresh_token": token} | changes)
    body: dict[str, Any] = response.json()
    return body


def session_status(client: TestClient, access_token: str) -> int:
    headers = {"Authorization": f"Bearer {access_token}"}
    return client.get("/oauth2/user/session", headers=headers).status_code


def last_log(app: FastAPI) -> ActivityLog:
    with Session(app.state.engine) as session:
        newest = select(ActivityLog).order_by(ActivityLog.id.desc()).limit(1)
        return session.scalars(newest).one()


def test_a_refresh_replaces_the_pair_in_its_family(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    first = login(client, admin_login)
    second = refresh(client, first["refresh_token"])
    assert second.keys() == {
        "token_type",
        "expires_in",
        "access_token",
        "refresh_token",
        "scope",
    }
    assert session_status(client, first["access_token"]) == 401  # the old pair is dead
    assert session_status(client, second["access_token"]) == 200
    with Session(app.state.engine) as session:
        rows = session.scalars(select(OAuth2Token).order_by(OAuth2Token.id)).all()
    assert [row.family_id for row in rows] == [rows[0].id, rows[0].id]
    assert [row.revoked_at is None for row in rows] == [False, True]
    log = last_log(app)
    assert (log.action, log.result, log.actor_email) == (
        "token_refresh",
        "ok",
        "admin@x.de",
    )


def test_a_reused_refresh_token_kills_the_whole_family(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    first = login(client, admin_login)
    with Session(app.state.engine) as session:
        family = session.scalars(select(OAuth2Token.family_id)).one()
    second = refresh(client, first["refresh_token"])
    again = refresh(client, first["refresh_token"])  # the old one, a second time
    assert again == {"error": "invalid_grant"}
    log = last_log(app)
    assert (log.action, log.reason, log.details) == (
        "token_refresh",
        "reused",
        f"family {family}",
    )
    assert session_status(client, second["access_token"]) == 401  # the newest pair too
    assert refresh(client, second["refresh_token"]) == {"error": "invalid_grant"}


def test_a_refresh_is_refused_with_a_reason(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    token = login(client, admin_login)["refresh_token"]
    # F-7: the frontend's "Bearer " prefix makes it an unknown token.
    assert refresh(client, f"Bearer {token}") == {"error": "invalid_grant"}
    assert last_log(app).reason == "unknown"
    # More scopes than the login got: refused, and the token stays usable.
    assert refresh(client, token, scope="admin user") == {"error": "invalid_scope"}
    with Session(app.state.engine) as session:
        other = session.get_one(OAuth2Client, "test-client")
        session.add(
            OAuth2Client(
                identifier="other",
                version=1,
                name="other",
                redirect_uris="[]",
                is_confidential=False,
                created_at=other.created_at,
                updated_at=other.created_at,
            )
        )
        session.commit()
    assert refresh(client, token, client_id="other") == {"error": "invalid_grant"}
    assert last_log(app).reason == "other_client"
    at(app, now() + timedelta(days=1))
    assert refresh(client, token) == {"error": "invalid_grant"}
    assert last_log(app).reason == "expired"


def test_a_role_taken_away_does_not_come_back_with_a_refresh(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    token = login(client, admin_login)["refresh_token"]
    with Session(app.state.engine) as session:
        session.execute(delete(UserRole))
        session.commit()
    lost = "The account no longer holds a scope of this token."
    for scope in ("admin", ""):  # asked for, or the old ones by default
        assert refresh(client, token, scope=scope) == {
            "error": "invalid_scope",
            "error_description": lost,
        }


def test_no_token_of_a_login_outlives_the_session(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    at(app, LOGIN_TIME)
    token = login(client, admin_login)["refresh_token"]
    for hours in range(1, 7):  # refreshed every hour, as the frontend does
        at(app, LOGIN_TIME + timedelta(hours=hours))
        pair = refresh(client, token)
        assert pair["expires_in"] == 7200
        token = pair["refresh_token"]
    at(app, LOGIN_TIME + timedelta(hours=7))
    last = refresh(client, token)
    assert last["expires_in"] == 3600  # only up to the session's end at 8 h
    with Session(app.state.engine) as session:
        newest = session.scalars(
            select(OAuth2Token).order_by(OAuth2Token.id.desc()).limit(1)
        ).one()
    session_end = LOGIN_TIME + timedelta(hours=8)
    assert (newest.access_expires_at, newest.refresh_expires_at) == (
        session_end,
        session_end,
    )
    at(app, session_end)
    assert refresh(client, last["refresh_token"]) == {"error": "invalid_grant"}


def test_a_refresh_after_logout_is_revoked_not_reused(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    first = login(client, admin_login)  # one login, one family
    assert (
        logout(client, first["access_token"]) == 200
    )  # ends the login (reason "logout")
    assert refresh(client, first["refresh_token"]) == {"error": "invalid_grant"}
    assert last_log(app).reason == "revoked"  # NOT "reused": no false theft row
    with Session(app.state.engine) as session:
        reasons = {r.revoked_reason for r in session.scalars(select(OAuth2Token)).all()}
    assert reasons == {"logout"}  # family was not re-killed into "reused"


def test_a_refresh_after_a_password_change_is_revoked_not_reused(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))  # a plain user
    form = {
        "grant_type": "password",
        "username": "anna@x.de",
        "password": "anna-pw-1",
        "client_id": "test-client",
        "scope": "user",
    }
    pair = client.post(URL, data=form).json()  # her login pair
    changed = client.patch(
        f"/user/{anna}", json={"password": "another-long-pw-2"}, headers=admin
    )
    assert changed.status_code == 200  # revokes her tokens ("password changed")
    assert refresh(client, pair["refresh_token"], scope="user") == {
        "error": "invalid_grant"
    }
    assert last_log(app).reason == "revoked"  # NOT "reused"
    with Session(app.state.engine) as session:
        reasons = {r.revoked_reason for r in session.scalars(select(OAuth2Token)).all()}
    assert "reused" not in reasons  # no false theft row
