from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import UserGroup, UserToUserGroup

URL = "/oauth2/user/token"


def bearer(client: TestClient, form: dict[str, str]) -> dict[str, str]:
    token = client.post(URL, data=form).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_the_admin_sees_the_three_lists(
    app: FastAPI,
    client: TestClient,
    admin_login: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"), enabled=False)
    now = datetime(2026, 11, 3)
    with Session(app.state.engine) as session:
        for group_id in (2, 1):
            session.add(
                UserGroup(
                    id=group_id,
                    description=f"g{group_id}",
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                UserToUserGroup(
                    user_id=anna, user_group_id=group_id, created_at=now, updated_at=now
                )
            )
        session.commit()
    admin = bearer(client, admin_login)

    assert client.get("/users", headers=admin).json() == [
        {
            "id": anna,
            "name": "anna",
            "email": "anna@x.de",
            "role": "user",
            "groups": [1, 2],
            "enabled": False,
        }
    ]
    admins = client.get("/admins", headers=admin).json()
    assert [(a["email"], a["role"]) for a in admins] == [("admin@x.de", "admin")]
    assert client.get("/user_groups", headers=admin).json() == [
        {"id": 1, "description": "g1"},
        {"id": 2, "description": "g2"},
    ]


def test_a_user_token_sees_none_of_them(
    client: TestClient, admin_login: dict[str, str], add_user: Callable[..., int]
) -> None:
    add_user("anna@x.de", hash_password("anna-pw-1"))
    user = bearer(
        client,
        admin_login
        | {"username": "anna@x.de", "password": "anna-pw-1", "scope": "user"},
    )
    for path in ("/users", "/admins", "/user_groups"):
        response = client.get(path, headers=user)
        assert (response.status_code, response.json()["error"]) == (
            403,
            "insufficient_scope",
        )
        assert 'error="insufficient_scope"' in response.headers["WWW-Authenticate"]
