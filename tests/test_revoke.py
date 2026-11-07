from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.models import ActivityLog, OAuth2Token

TOKEN = "/oauth2/user/token"
REVOKE = "/oauth2/user/revoke"


def login(client: TestClient, admin_login: dict[str, str]) -> dict[str, Any]:
    body: dict[str, Any] = client.post(TOKEN, data=admin_login).json()
    return body


def refresh(client: TestClient, token: str) -> dict[str, Any]:
    form = {"grant_type": "refresh_token", "client_id": "test-client", "scope": "admin"}
    body: dict[str, Any] = client.post(
        TOKEN, data=form | {"refresh_token": token}
    ).json()
    return body


def revoke(client: TestClient, token: str, **changes: str) -> int:
    form = {"token": token, "client_id": "test-client"} | changes
    return client.post(REVOKE, data=form).status_code


def session_status(client: TestClient, access_token: str) -> int:
    headers = {"Authorization": f"Bearer {access_token}"}
    return client.get("/oauth2/user/session", headers=headers).status_code


def logout_rows(app: FastAPI) -> list[ActivityLog]:
    with Session(app.state.engine) as session:
        rows = select(ActivityLog).where(ActivityLog.action == "logout")
        return list(session.scalars(rows))


def test_revoking_the_refresh_token_ends_the_login(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    pair = login(client, admin_login)
    assert revoke(client, pair["refresh_token"]) == 200
    assert session_status(client, pair["access_token"]) == 401
    assert refresh(client, pair["refresh_token"]) == {"error": "invalid_grant"}
    rows = logout_rows(app)
    assert [(row.result, row.actor_email) for row in rows] == [("ok", "admin@x.de")]


def test_the_access_token_ends_the_login_too(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    pair = login(client, admin_login)
    assert revoke(client, pair["access_token"]) == 200
    assert refresh(client, pair["refresh_token"]) == {"error": "invalid_grant"}


def test_an_old_token_of_the_login_ends_the_newest_pair(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    first = login(client, admin_login)
    second = refresh(client, first["refresh_token"])
    assert revoke(client, first["refresh_token"]) == 200
    assert session_status(client, second["access_token"]) == 401


def test_another_login_of_the_same_user_stays(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    mine = login(client, admin_login)
    other = login(client, admin_login)
    assert revoke(client, mine["refresh_token"]) == 200
    assert session_status(client, other["access_token"]) == 200


def test_an_unknown_token_gets_200_and_writes_nothing(
    app: FastAPI, client: TestClient
) -> None:
    assert revoke(client, "made-up") == 200
    assert logout_rows(app) == []
    with Session(app.state.engine) as session:
        assert session.scalars(select(OAuth2Token)).all() == []


def test_a_login_logged_out_twice_has_one_row(
    app: FastAPI, client: TestClient, admin_login: dict[str, str]
) -> None:
    pair = login(client, admin_login)
    assert revoke(client, pair["refresh_token"]) == 200
    assert revoke(client, pair["refresh_token"]) == 200
    assert len(logout_rows(app)) == 1


def test_an_unknown_client_changes_nothing(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    pair = login(client, admin_login)
    assert revoke(client, pair["refresh_token"], client_id="nobody") == 401
    assert session_status(client, pair["access_token"]) == 200


def test_a_request_without_a_token_is_refused(client: TestClient) -> None:
    response = client.post(REVOKE, data={"client_id": "test-client"})
    assert (response.status_code, response.json()["error"]) == (400, "invalid_request")


def test_a_query_string_is_refused(
    client: TestClient, admin_login: dict[str, str]
) -> None:
    pair = login(client, admin_login)
    form = {"token": pair["refresh_token"], "client_id": "test-client"}
    assert client.post(f"{REVOKE}?a=%zz", data=form).status_code == 400
    assert session_status(client, pair["access_token"]) == 200
