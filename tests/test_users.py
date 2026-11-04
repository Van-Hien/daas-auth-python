from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, OAuth2Token, User, UserGroup

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def test_get_a_user(
    client: TestClient, admin: dict[str, str], add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"), enabled=False)
    response = client.get(f"/user/{anna}", headers=admin)
    assert response.status_code == 200
    assert response.json() == {
        "id": anna,
        "name": "anna",
        "email": "anna@x.de",
        "role": "user",
        "groups": [],
        "enabled": False,
    }


def test_an_admins_id_gives_the_admin(
    client: TestClient, admin: dict[str, str]
) -> None:
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    assert client.get(f"/user/{me}", headers=admin).json() == {
        "id": me,
        "name": "Admin",
        "email": "admin@x.de",
        "role": "admin",
    }


def test_a_user_token_cannot_get_a_user(
    client: TestClient, login: Login, add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    response = client.get(
        f"/user/{anna}", headers=login("anna@x.de", "anna-pw-1", "user")
    )
    assert (response.status_code, response.json()["error"]) == (
        403,
        "insufficient_scope",
    )


def test_an_unknown_id_is_404_problem(
    client: TestClient, admin: dict[str, str]
) -> None:
    response = client.get("/user/999", headers=admin)
    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM
    assert response.json()["detail"] == "No account has the id 999."


def new_user(**fields: object) -> dict[str, object]:
    return {
        "name": "Anna",
        "email": "Anna@X.de",
        "password": "a-long-enough-pw",
        "groups": [],
    } | fields


def test_an_admin_creates_a_disabled_user_in_a_group(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_groups(app, 1, 2)
    response = client.post("/user", json=new_user(groups=[2, 1, 2]), headers=admin)
    assert response.status_code == 200
    created = response.json()
    assert created | {"id": 0} == {
        "id": 0,
        "name": "Anna",
        "email": "anna@x.de",
        "role": "user",
        "groups": [1, 2],
        "enabled": False,
    }
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    with Session(app.state.engine) as session:
        user = session.get_one(User, created["id"])
        assert (user.created_by, user.updated_by) == (me, me)
        assert user.password.startswith("$argon2id$")
        row = session.scalars(
            select(ActivityLog).order_by(ActivityLog.id.desc())
        ).first()
        assert row is not None
        assert (row.action, row.target_id, row.created_by) == (
            "user_create",
            created["id"],
            me,
        )


def test_a_new_user_cannot_log_in_before_an_admin_enables_them(
    client: TestClient, admin: dict[str, str]
) -> None:
    client.post("/user", json=new_user(), headers=admin)
    form = {
        "grant_type": "password",
        "username": "anna@x.de",
        "password": "a-long-enough-pw",
        "client_id": "test-client",
        "scope": "user",
    }
    assert client.post("/oauth2/user/token", data=form).status_code == 400


def test_creating_a_user_needs_an_admin(
    client: TestClient, login: Login, add_user: Callable[..., int]
) -> None:
    assert client.post("/user", json=new_user()).status_code == 401
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert client.post("/user", json=new_user(), headers=user).status_code == 403


def test_refusals_of_post_user(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_groups(app, 1)
    cases = [
        (new_user(groups=[1, 7, 8]), 422, "No user group has the id 7, 8."),
        (new_user(password="short"), 400, None),
        (new_user(email="no-at-sign"), 400, None),
        (new_user(role="admin"), 400, None),  # unknown fields are refused
        ({"name": "incomplete"}, 400, None),  # the suite's row 7
    ]
    for body, status, detail in cases:
        response = client.post("/user", json=body, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            status,
            PROBLEM,
        ), body
        if detail:
            assert response.json()["detail"] == detail
    assert client.post("/user", json=new_user(), headers=admin).status_code == 200
    again = client.post("/user", json=new_user(email=" anna@x.DE"), headers=admin)
    assert (again.status_code, again.json()["detail"]) == (
        409,
        "An account with this email exists already.",
    )


def add_groups(app: FastAPI, *ids: int) -> None:
    now = datetime(2026, 11, 3)
    with Session(app.state.engine) as session:
        for group_id in ids:
            session.add(
                UserGroup(
                    id=group_id,
                    description=f"g{group_id}",
                    created_at=now,
                    updated_at=now,
                )
            )
        session.commit()


def user_form(email: str, password: str) -> dict[str, str]:
    return {
        "grant_type": "password",
        "username": email,
        "password": password,
        "client_id": "test-client",
        "scope": "user",
    }


def test_an_admin_enables_and_disables_a_user(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
) -> None:
    anna = client.post("/user", json=new_user(), headers=admin).json()["id"]
    enabled = client.post(f"/user/{anna}/enable", headers=admin)
    assert (enabled.status_code, enabled.json()["enabled"]) == (200, True)
    session = login("anna@x.de", "a-long-enough-pw", "user")
    assert client.get("/oauth2/user/session", headers=session).status_code == 200

    disabled = client.post(f"/user/{anna}/disable", headers=admin)
    assert (disabled.status_code, disabled.json()["enabled"]) == (200, False)
    assert client.get("/oauth2/user/session", headers=session).status_code == 401


def test_patch_changes_only_what_was_sent(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_groups(app, 1, 2)
    anna = client.post("/user", json=new_user(groups=[1]), headers=admin).json()["id"]
    response = client.patch(
        f"/user/{anna}", json={"name": "Anna B", "groups": [2]}, headers=admin
    )
    assert (response.status_code, response.json()) == (200, {"message": "User updated"})
    assert client.get(f"/user/{anna}", headers=admin).json() | {"id": 0} == {
        "id": 0,
        "name": "Anna B",
        "email": "anna@x.de",
        "role": "user",
        "groups": [2],
        "enabled": False,
    }


def test_a_new_password_ends_the_users_sessions(
    client: TestClient, admin: dict[str, str]
) -> None:
    anna = client.post("/user", json=new_user(), headers=admin).json()["id"]
    client.post(f"/user/{anna}/enable", headers=admin)
    old = client.post(
        "/oauth2/user/token", data=user_form("anna@x.de", "a-long-enough-pw")
    )
    session = {"Authorization": f"Bearer {old.json()['access_token']}"}

    new_password = {"password": "another-long-pw-2"}
    assert (
        client.patch(f"/user/{anna}", json=new_password, headers=admin).status_code
        == 200
    )
    assert client.get("/oauth2/user/session", headers=session).status_code == 401
    form = user_form("anna@x.de", "another-long-pw-2")
    assert client.post("/oauth2/user/token", data=form).status_code == 200


def test_refusals_of_the_user_changes(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    client.post("/user", json=new_user(email="bob@x.de"), headers=admin)
    anna = client.post("/user", json=new_user(), headers=admin).json()["id"]
    taken = client.patch(f"/user/{anna}", json={"email": "BOB@x.de"}, headers=admin)
    assert taken.status_code == 409
    response = client.post("/user/999/enable", headers=admin)
    assert (response.status_code, response.headers["content-type"]) == (404, PROBLEM)
    add_user("carl@x.de", hash_password("carl-pw-1"))
    user = login("carl@x.de", "carl-pw-1", "user")
    assert client.post(f"/user/{anna}/enable", headers=user).status_code == 403
    assert client.patch(f"/user/{anna}", json={}, headers=user).status_code == 403


def test_an_admin_deletes_a_user_and_the_users_tokens(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    add_groups(app, 1)
    anna = client.post("/user", json=new_user(groups=[1]), headers=admin).json()["id"]
    client.post(f"/user/{anna}/enable", headers=admin)
    form = user_form("anna@x.de", "a-long-enough-pw")
    token = client.post("/oauth2/user/token", data=form).json()["access_token"]

    response = client.delete(f"/user/{anna}", headers=admin)
    assert (response.status_code, response.json()) == (200, "User deleted")
    assert client.get(f"/user/{anna}", headers=admin).status_code == 404
    gone = client.get(
        "/oauth2/user/session", headers={"Authorization": f"Bearer {token}"}
    )
    assert gone.status_code == 401
    with Session(app.state.engine) as session:
        assert (
            session.scalars(
                select(OAuth2Token).where(OAuth2Token.user_id == anna)
            ).all()
            == []
        )


def test_refusals_of_delete_user(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    response = client.delete("/user/999", headers=admin)
    assert (response.status_code, response.headers["content-type"]) == (404, PROBLEM)
    bob = add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert client.delete(f"/user/{bob}", headers=user).status_code == 403
