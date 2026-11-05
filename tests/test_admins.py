from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import Role, UserRole

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]
NEW_ADMIN = {"name": "Bea", "email": "Bea@x.de", "password": "a-long-admin-pw-1"}


def test_an_admin_adds_an_admin_who_can_log_in_at_once(
    client: TestClient, admin: dict[str, str], login: Login
) -> None:
    response = client.post("/admin", json=NEW_ADMIN, headers=admin)
    assert response.status_code == 200
    bea = response.json()
    assert bea | {"id": 0} == {
        "id": 0,
        "name": "Bea",
        "email": "bea@x.de",
        "role": "admin",
    }
    assert [a["id"] for a in client.get("/admins", headers=admin).json()][-1] == bea[
        "id"
    ]
    headers = login("bea@x.de", "a-long-admin-pw-1", "admin")
    assert client.get("/users", headers=headers).status_code == 200


def test_an_admin_deletes_another_admin(
    client: TestClient, admin: dict[str, str]
) -> None:
    bea = client.post("/admin", json=NEW_ADMIN, headers=admin).json()["id"]
    response = client.delete(f"/admin/{bea}", headers=admin)
    assert (response.status_code, response.json()) == (200, "admin deleted")
    assert client.get(f"/user/{bea}", headers=admin).status_code == 404


def test_no_admin_deletes_themselves(client: TestClient, admin: dict[str, str]) -> None:
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    response = client.delete(f"/admin/{me}", headers=admin)
    assert (response.status_code, response.headers["content-type"]) == (409, PROBLEM)
    assert response.json()["detail"] == "An admin cannot delete their own account."


def test_the_last_admin_stays(
    app: FastAPI, client: TestClient, admin: dict[str, str], login: Login
) -> None:
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    bea = client.post("/admin", json=NEW_ADMIN, headers=admin).json()["id"]
    as_bea = login("bea@x.de", "a-long-admin-pw-1", "admin")
    # Bea loses the role, but her token still carries the admin scope.
    with Session(app.state.engine) as session:
        user_role = session.scalars(select(Role.id).where(Role.name == "user")).one()
        session.execute(
            update(UserRole).where(UserRole.user_id == bea).values(role_id=user_role)
        )
        session.commit()
    response = client.delete(f"/admin/{me}", headers=as_bea)
    assert (response.status_code, response.json()["detail"]) == (
        409,
        "The last admin cannot be deleted.",
    )


def test_refusals_of_the_admin_routes(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    for admin_id in (anna, 999):  # a user is no admin
        response = client.delete(f"/admin/{admin_id}", headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            404,
            PROBLEM,
        )
    taken = client.post(
        "/admin", json=NEW_ADMIN | {"email": "ANNA@x.de"}, headers=admin
    )
    assert taken.status_code == 409
    user = login("anna@x.de", "anna-pw-1", "user")
    assert client.post("/admin", json=NEW_ADMIN, headers=user).status_code == 403
    assert client.delete(f"/admin/{anna}", headers=user).status_code == 403


def test_the_user_routes_refuse_an_admin(
    client: TestClient, admin: dict[str, str]
) -> None:
    bea = client.post("/admin", json=NEW_ADMIN, headers=admin).json()["id"]
    calls = [
        ("PATCH", f"/user/{bea}", {"name": "Eve"}),
        ("POST", f"/user/{bea}/disable", None),
        ("POST", f"/user/{bea}/enable", None),
        ("DELETE", f"/user/{bea}", None),
    ]
    for method, path, body in calls:
        response = client.request(method, path, json=body, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            409,
            PROBLEM,
        )
        assert f"/admin/{bea}" in response.json()["detail"]
    admins = client.get("/admins", headers=admin).json()
    assert [a["name"] for a in admins if a["id"] == bea] == ["Bea"]  # unchanged


def test_an_admin_reads_an_admin(client: TestClient, admin: dict[str, str]) -> None:
    bea = client.post("/admin", json=NEW_ADMIN, headers=admin).json()
    response = client.get(f"/admin/{bea['id']}", headers=admin)
    assert (response.status_code, response.json()) == (200, bea)


def test_a_user_token_cannot_read_an_admin(
    client: TestClient, add_user: Callable[..., int], login: Login
) -> None:
    add_user("anna@x.de", hash_password("anna-pw-1"))
    headers = login("anna@x.de", "anna-pw-1", "user")
    assert client.get("/admin/1", headers=headers).status_code == 403


def test_reading_an_id_that_is_no_admin_is_404(
    client: TestClient,
    admin: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    assert client.get("/admin/9999", headers=admin).status_code == 404
    assert client.get(f"/admin/{anna}", headers=admin).status_code == 404
